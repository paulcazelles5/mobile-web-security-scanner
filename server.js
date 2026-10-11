import http from "node:http";
import dns from "node:dns/promises";
import net from "node:net";
import { URL } from "node:url";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const send = (res, status, data) => {
  res.writeHead(status, {"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff"});
  res.end(JSON.stringify(data));
};
function private4(ip) {
  const p=ip.split(".").map(Number);
  return p.length!==4 || p.some(n=>!Number.isInteger(n)||n<0||n>255) || p[0]===0 || p[0]===10 || p[0]===127 ||
    (p[0]===169&&p[1]===254)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||
    (p[0]===100&&p[1]>=64&&p[1]<=127)||p[0]>=224;
}
function private6(ip) {
  const x=ip.toLowerCase().split("%")[0];
  return x==="::"||x==="::1"||x.startsWith("fc")||x.startsWith("fd")||/^fe[89ab]/.test(x)||x.startsWith("ff")||
    x.startsWith("::ffff:127.")||x.startsWith("::ffff:10.")||x.startsWith("::ffff:192.168.");
}
async function checkTarget(u) {
  if (!["http:","https:"].includes(u.protocol)||u.username||u.password) throw Error("Use a valid HTTP or HTTPS URL without credentials.");
  const host=u.hostname.replace(/^\[|\]$/g,"").toLowerCase();
  if (host==="localhost"||host.endsWith(".localhost")||host.endsWith(".local")||host.endsWith(".internal")) throw Error("Local and internal hosts are blocked.");
  const family=net.isIP(host);
  if (family===4&&private4(host)||family===6&&private6(host)) throw Error("Private or reserved IP addresses are blocked.");
  if (!family) {
    let records;
    try { records=await dns.lookup(host,{all:true,verbatim:true}); } catch { throw Error("The hostname could not be resolved."); }
    if (!records.length||records.some(r=>r.family===4?private4(r.address):private6(r.address))) throw Error("The hostname resolves to a private or reserved address and is blocked.");
  }
}
async function fetchTarget(start) {
  let u=new URL(start); const redirects=[];
  for(let i=0;i<=5;i++) {
    await checkTarget(u);
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),8000);
    let r;
    try { r=await fetch(u,{method:"GET",redirect:"manual",signal:controller.signal,headers:{"user-agent":"MobileWebSecurityScanner/1.0"}}); }
    catch(e) { throw Error(e.name==="AbortError"?"The target timed out.":"Could not connect to the target."); }
    finally { clearTimeout(timer); }
    if([301,302,303,307,308].includes(r.status)) {
      const loc=r.headers.get("location"); await r.body?.cancel();
      if(!loc) return {response:r,url:u.href,redirects,body:""};
      if(i===5) throw Error("Too many redirects.");
      const next=new URL(loc,u); redirects.push({status:r.status,from:u.href,to:next.href}); u=next; continue;
    }
    const reader=r.body?.getReader(); let body="",size=0,truncated=false;
    if(reader) while(true) { const {done,value}=await reader.read(); if(done) break; size+=value.byteLength; if(size>1000000){truncated=true;await reader.cancel();break;} body+=new TextDecoder().decode(value,{stream:true}); }
    return {response:r,url:u.href,redirects,body,truncated};
  }
  throw Error("Redirect limit reached.");
}
function analyze({response,url,redirects,body,truncated=false}) {
  const h=response.headers, https=url.startsWith("https:"), findings=[];
  const add=(severity,title,evidence,fix)=>findings.push({severity,title,evidence,fix});
  const checks=[
    ["content-security-policy","Content-Security-Policy","high","Define a policy that restricts script, style, image and connection sources."],
    ["strict-transport-security","Strict-Transport-Security","medium","On HTTPS sites, configure HSTS with an appropriate max-age."],
    ["x-content-type-options","X-Content-Type-Options","low","Set X-Content-Type-Options: nosniff."],
    ["referrer-policy","Referrer-Policy","low","Set a policy such as strict-origin-when-cross-origin."],
    ["permissions-policy","Permissions-Policy","low","Disable browser features the site does not need."],
    ["x-frame-options","X-Frame-Options","low","Use CSP frame-ancestors and consider X-Frame-Options for legacy support."]
  ];
  for(const [key,name,severity,fix] of checks) if(!h.get(key)) {
    if(key==="strict-transport-security"&&!https) add("info",name+" not checked on HTTP","HSTS is meaningful only over HTTPS.","Enable HTTPS first, then configure HSTS.");
    else add(severity,"Missing "+name,"The response does not include the "+name+" header.",fix);
  }
  if(!https) add("high","Page uses HTTP","The final URL is not encrypted with HTTPS.","Enable HTTPS and redirect HTTP traffic to HTTPS.");
  if(h.get("server")) add("info","Server banner exposed","Server: "+h.get("server),"Consider reducing unnecessary server/version details.");
  if(h.get("x-powered-by")) add("low","Technology banner exposed","X-Powered-By: "+h.get("x-powered-by"),"Remove X-Powered-By if it reveals unnecessary details.");
  const cookies=typeof h.getSetCookie==="function"?h.getSetCookie():(h.get("set-cookie")?[h.get("set-cookie")]:[]);
  for(const c of cookies){const n=(c.split("=")[0]||"cookie").trim(),l=c.toLowerCase();
    if(https&&!l.includes("secure")) add("medium","Cookie "+n+" lacks Secure","Cookie may lack the Secure attribute.","Add Secure to cookies intended only for HTTPS.");
    if(!l.includes("httponly")) add("low","Cookie "+n+" lacks HttpOnly","Cookie may lack HttpOnly.","Add HttpOnly to session cookies that JavaScript need not access.");
    if(!l.includes("samesite")) add("low","Cookie "+n+" lacks SameSite","Cookie may lack SameSite.","Set an appropriate SameSite value, often Lax.");
  }
  const forms=[...body.matchAll(/<form\b[^>]*>/gi)].map(m=>m[0]).slice(0,30);
  const insecure=forms.filter(f=>/\baction\s*=\s*["']?http:\/\//i.test(f));
  if(insecure.length) add("high","Form submits to HTTP",insecure.length+" form(s) appear to submit to HTTP.","Submit forms over HTTPS.");
  if(/<input\b[^>]*type\s*=\s*["']?password/i.test(body)&&!https) add("high","Password field on HTTP page","Password input found on an unencrypted page.","Use HTTPS before collecting credentials.");
  const rank={critical:0,high:1,medium:2,low:3,info:4}; findings.sort((a,b)=>rank[a.severity]-rank[b.severity]);
  const summary=Object.fromEntries(["critical","high","medium","low","info"].map(s=>[s,findings.filter(f=>f.severity===s).length]));
  return {scannedAt:new Date().toISOString(),url,status:response.status,statusText:response.statusText,redirects,headers:Object.fromEntries(h.entries()),truncated,summary:{total:findings.length,...summary},findings,notes:["Heuristic scan of one HTTP response, not a full penetration test.","A missing header is not automatically an exploitable vulnerability; review findings in context.",...(truncated?["Response body exceeded the scan limit; some HTML checks may be incomplete."]:[])]};
}
const server=http.createServer(async(req,res)=>{
  if(req.method==="GET"&&req.url==="/api/health") return send(res,200,{ok:true});
  if(req.method==="GET"&&["/","/index.html","/style.css","/app.js"].includes(req.url)){
    const name=req.url==="/"||req.url==="/index.html"?"index.html":req.url.slice(1);
    const types={"index.html":"text/html; charset=utf-8","style.css":"text/css; charset=utf-8","app.js":"text/javascript; charset=utf-8"};
    try{const b=await readFile(path.join(PUBLIC_DIR,name));res.writeHead(200,{"content-type":types[name],"x-content-type-options":"nosniff","cache-control":"no-store"});return res.end(b);}
    catch{return send(res,500,{error:"UI files are missing."});}
  }
  if(req.method!=="POST"||req.url!=="/api/scan") return send(res,404,{error:"Not found"});
  let raw="";req.setEncoding("utf8");
  for await(const chunk of req){raw+=chunk;if(raw.length>10000)return send(res,413,{error:"Request too large."});}
  try{const d=JSON.parse(raw||"{}");if(typeof d.url!=="string"||d.url.length>2048)return send(res,400,{error:"Provide a URL (maximum 2048 characters)."});
    let u;try{u=new URL(d.url.includes("://")?d.url:"https://"+d.url);}catch{return send(res,400,{error:"That URL is not valid."});}
    if(!u.hostname)return send(res,400,{error:"Provide a valid hostname."});
    return send(res,200,analyze(await fetchTarget(u.href)));
  }catch(e){return send(res,400,{error:e.message||"Scan failed."});}
});
server.listen(PORT,HOST,()=>console.log("Mobile Web Security Scanner listening on "+HOST+":"+PORT));