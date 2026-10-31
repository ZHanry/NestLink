// Real Chrome against the original private gateway through actual Caddy TLS.
// The hosted driver installs a temporary CA in OS/NSS; no TLS errors are ignored.
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const crypto = require('node:crypto');
const args = {};
for (let i=2;i<process.argv.length;i+=2) args[process.argv[i].replace(/^--/,'')]=process.argv[i+1];
const directory = path.resolve(args.directory || '');
if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted' || !directory.startsWith(path.resolve(process.env.RUNNER_TEMP || '')+path.sep)) throw new Error('R02 hosted private directory required');
const input=JSON.parse(fs.readFileSync(path.join(directory,'browser-input.json'),'utf8'));
const report={schema_version:1,passed:false,scope:'Real Chrome/Caddy TLS, simulated hosted DNS and temporary CA; not Internet/ACME or installed daemon acceptance',certificate_errors_ignored:false,completed_cases:[],error_case:null};
let active='setup';let browser;
const check=(value,code)=>{if(!value)throw new Error(code);};
const mark=name=>report.completed_cases.push(name);
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const write=(name,value)=>fs.writeFileSync(path.join(directory,name),JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
async function command(action) {
  let sequence=1;while(fs.existsSync(path.join(directory,`command-${sequence}.json`)))sequence++;
  const pending=path.join(directory,`command-${sequence}.pending`);
  fs.writeFileSync(pending,JSON.stringify({sequence,action}),{flag:'wx',mode:0o600});
  fs.renameSync(pending,path.join(directory,`command-${sequence}.json`));
  const end=Date.now()+15000;
  while(Date.now()<end){
    const ack=path.join(directory,`ack-${sequence}.json`);
    if(fs.existsSync(ack)){try{return JSON.parse(fs.readFileSync(ack,'utf8'));}catch(error){if(!(error instanceof SyntaxError))throw error;}}
    await delay(25);
  }
  throw new Error('original-owner-command-timeout');
}
async function launch(page,service) {
  const response=await page.goto(service.launch_url,{waitUntil:'domcontentloaded'});
  check(response.status()===200,'launch-page-refused');
  const security=response.securityDetails();
  check(security && security.protocol().startsWith('TLS'),'real-browser-tls-required');
  await page.waitForFunction(()=>location.hash==='' && document.querySelector('#application')!==null,{timeout:15000});
  check(page.url()===service.origin+'/','fragment-ticket-not-removed');
  const cookies=(await browser.cookies()).filter(cookie=>cookie.domain===new URL(service.origin).hostname);
  const session=cookies.find(cookie=>cookie.name==='__Host-nl_private_web');
  check(session && session.secure && session.httpOnly && session.sameSite==='Strict' && session.path==='/' && session.domain===new URL(service.origin).hostname,'browser-session-cookie-boundary');
  check(!(await page.evaluate(()=>document.cookie)).includes('__Host-nl_private_web'),'http-only-cookie-readable');
  check(!cookies.some(cookie=>cookie.name==='login'),'backend-cookie-exposed-to-browser');
  return session;
}
async function login(page) {
  const result=await page.evaluate(async()=>{
    const login=await fetch('/login',{method:'POST'});
    const me=await fetch('/me');
    return {login:login.status,me:me.status,body:await me.text(),browserCookie:document.cookie};
  });
  check(result.login===200 && result.me===200 && result.body==='authenticated fixed target','original-backend-cookie-login-failed');
  check(!result.browserCookie.includes('login=accepted'),'backend-jar-leaked');
}
async function socket(page) {
  const result=await page.evaluate(()=>new Promise(resolve=>{
    const socket=new WebSocket(location.origin.replace('https:','wss:')+'/socket');
    window.fixtureSocket=socket;window.fixtureSocketClosed=false;
    const timeout=setTimeout(()=>resolve(false),10000);
    socket.onopen=()=>socket.send('original private websocket');
    socket.onmessage=event=>{if(event.data==='original private websocket'){clearTimeout(timeout);window.fixtureKeepalive=setInterval(()=>{if(socket.readyState===WebSocket.OPEN)socket.send('keepalive');},500);resolve(true);}};
    socket.onclose=()=>{window.fixtureSocketClosed=true;clearInterval(window.fixtureKeepalive);};
    socket.onerror=()=>{clearTimeout(timeout);resolve(false);};
  }));
  check(result,'real-browser-websocket-upgrade-or-echo-failed');
}
(async()=>{
  try{
    const tools=path.resolve(args.tools);
    check(require(path.join(tools,'package.json')).version==='25.14.0','reviewed-puppeteer-required');
    const {default:puppeteer}=await import(pathToFileURL(path.join(tools,'lib/puppeteer/puppeteer-core.js')).href);
    browser=await puppeteer.launch({executablePath:args.chrome,headless:true,userDataDir:path.join(directory,'chrome-profile'),args:['--no-proxy-server']});
    report.browser_version=await browser.version();
    report.browser_executable_sha256=crypto.createHash('sha256').update(fs.readFileSync(args.chrome)).digest('hex');
    check(!browser.process().spawnargs.some(arg=>/ignore-certificate-errors|ignore-urlfetcher-cert-requests|allow-insecure-localhost/.test(arg)),'certificate-bypass-present');
    const management=await browser.newPage();management.setDefaultTimeout(15000);
    active='management-origin-cookie-sentinel';
    const control=await management.goto(input.management,{waitUntil:'domcontentloaded'});
    check(control.status()===200 && control.securityDetails(),'management-https-sentinel-unavailable');
    const initial=(await browser.cookies()).find(cookie=>cookie.name==='nl15_access' && cookie.domain===new URL(input.management).hostname);
    check(initial && initial.httpOnly && initial.secure,'management-sentinel-cookie-missing');
    const first=await browser.newPage();const second=await browser.newPage();
    first.setDefaultTimeout(15000);second.setDefaultTimeout(15000);
    active='single-use-fragment-and-real-secure-cookie';
    const old=await launch(first,input.services[0]);await launch(second,input.services[1]);
    write('browser-state.json',{old_cookie:`__Host-nl_private_web=${old.value}`});
    mark(active);
    active='single-use-ticket-replay-refused';
    const ticket=new URL(input.services[0].launch_url).hash.slice(1);
    const replay=await first.evaluate(async ticket=>(await fetch('/.nestlink/session',{method:'POST',headers:{Authorization:'NestLinkTicket '+ticket}})).status,ticket);
    check(replay===401,'launch-ticket-replayed');mark(active);
    active='original-cookie-login-and-cross-service-jar-isolation';
    await login(first);
    const before=await second.evaluate(async()=>(await fetch('/me')).status);
    check(before===403,'second-service-inherited-first-application-login');
    await first.evaluate(()=>{document.cookie='login=forged; Domain=example.net; Path=/; Secure';document.cookie='nl15_access=forged; Domain=example.com; Path=/; Secure';document.cookie='__Host-nl_private_web=forged; Domain=example.net; Path=/; Secure';});
    const isolated=await second.evaluate(async()=>(await fetch('/me')).status);
    check(isolated===403,'sibling-cookie-became-backend-authority');
    const after=(await browser.cookies()).find(cookie=>cookie.name==='nl15_access' && cookie.domain===new URL(input.management).hostname);
    check(after && after.value===initial.value && after.domain===initial.domain,'management-cookie-polluted');
    await login(second);mark(active);
    active='real-browser-file-upload-and-download';
    const bytes=await first.evaluate(async()=>{
      const payload=new Uint8Array(2048).fill(27);const file=new File([payload],'private-upload.bin',{type:'application/octet-stream'});
      const upload=await fetch('/upload',{method:'POST',body:file});const echoed=new Uint8Array(await upload.arrayBuffer());
      const download=await fetch('/download');const received=new Uint8Array(await download.arrayBuffer());
      return {upload:upload.status,echo:echoed.length===2048 && echoed.every(byte=>byte===27),download:download.status,bytes:received.length===2048 && received.every(byte=>byte===37)};
    });
    check(bytes.upload===200 && bytes.echo && bytes.download===200 && bytes.bytes,'private-file-bytes-changed');mark(active);
    active='same-origin-redirect-and-external-redirect-refusal';
    const redirected=await first.goto(input.services[0].origin+'/same',{waitUntil:'domcontentloaded'});
    check(redirected.status()===200 && first.url()===input.services[0].origin+'/me','same-service-redirect-failed');
    const outside=await first.evaluate(async()=>(await fetch('/outside',{redirect:'error'})).status);
    check(outside===502,'external-redirect-escaped');mark(active);
    active='cross-origin-browser-csrf-refused';
    const beforeCsrf=(await command('observe')).result.backend_login_count;
    const attacker=await browser.newPage();await attacker.goto(input.attacker,{waitUntil:'domcontentloaded'});
    const denied=await attacker.evaluate(async origin=>{try{const r=await fetch(origin+'/login',{method:'POST',credentials:'include'});return !r.ok;}catch(_){return true;}},input.services[0].origin);
    check(denied,'cross-origin-post-succeeded');
    check((await command('observe')).result.backend_login_count===beforeCsrf,'cross-origin-post-reached-private-backend');
    await attacker.close();mark(active);
    active='real-browser-websocket-and-logout-physical-close';
    await socket(first);
    check(await first.evaluate(async()=>(await fetch('/.nestlink/logout',{method:'POST'})).status)===204,'logout-refused');
    await first.waitForFunction(()=>window.fixtureSocketClosed===true,{timeout:5000});
    check(await first.evaluate(async()=>(await fetch('/me')).status)===401,'logout-session-still-usable');mark(active);
    active='original-management-acl-withdrawal-closes-existing-websocket';
    await socket(second);await command('revoke_second');
    await second.waitForFunction(()=>window.fixtureSocketClosed===true,{timeout:5000});
    check(await second.evaluate(async()=>(await fetch('/me')).status)===403,'revoked-private-acl-still-forwarded');mark(active);
    report.passed=true;
  }catch(error){report.error_case=active;report.error_kind=error?.constructor?.name||'Error';report.error_code=/^[a-z0-9-]{1,120}$/.test(error?.message||'')?error.message:'automation-operation-failed';}
  finally{
    if(browser){try{await browser.close();report.browser_closed=true;}catch(_){report.passed=false;report.browser_closed=false;}}
    write('browser-report.json',report);
  }
  process.exitCode=report.passed?0:1;
})();
