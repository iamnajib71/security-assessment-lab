/* Actual local dashboard capture. No generated data, external sites or user profile. */
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
let playwright;
for(const candidate of [process.env.PLAYWRIGHT_MODULE,'playwright',path.join(process.env.USERPROFILE || '', '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright')].filter(Boolean)) {
  try {playwright=require(candidate);break;} catch {}
}
if(!playwright) throw new Error('Install Playwright or set PLAYWRIGHT_MODULE to its module path');
const {chromium} = playwright;
const root = path.resolve(__dirname, '..');
const privateDir = path.join(root, 'private/monitoring');
const target = 'https://127.0.0.1:8443';
const env = Object.fromEntries(fs.readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/).filter(x => x.includes('=') && !x.startsWith('#')).map(x => [x.slice(0,x.indexOf('=')),x.slice(x.indexOf('=')+1)]));
const ca = fs.readFileSync(path.join(privateDir,'stack/config/wazuh_indexer_ssl_certs/root-ca.pem'));
const statePath = path.join(privateDir, 'browser-state.json');

function verifyTLS() {
  return new Promise((resolve,reject) => {
    const req = https.get(target+'/', {ca,servername:'wazuh.dashboard',rejectUnauthorized:true}, res => {res.resume();resolve(res.statusCode);});
    req.on('error', reject); req.setTimeout(15000, () => req.destroy(new Error('Local dashboard TLS probe timed out')));
  });
}

(async () => {
  const tlsStatus = await verifyTLS(); // Validate the generated CA + service identity first.
  const executable = ['C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',chromium.executablePath()].find(p => fs.existsSync(p));
  if(!executable) throw new Error('No installed Chrome/bundled Chromium');
  const browser = await chromium.launch({executablePath:executable,headless:true,args:['--disable-gpu','--renderer-process-limit=2','--disable-background-networking','--disable-component-update']});
  try {
    const context = await browser.newContext({viewport:{width:1440,height:1200},ignoreHTTPSErrors:true,...(fs.existsSync(statePath)?{storageState:statePath}:{})});
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      return url.origin === target || ['data:','blob:','about:'].includes(url.protocol) ? route.continue() : route.abort();
    });
    const page = await context.newPage();
    const browserErrors=[];
    page.on('pageerror',e=>browserErrors.push(e.stack || e.message));
    page.on('requestfailed',r=>browserErrors.push(r.url()+': '+r.failure()?.errorText));
    await page.goto(target, {waitUntil:'domcontentloaded',timeout:60000});
    await page.waitForFunction(()=>!document.body.innerText.trim().match(/^Loading\s*\.{0,3}$/i),{timeout:60000});
    const mode = process.argv[2] || 'inspect';
    if(mode === 'inspect') {
      console.log(JSON.stringify({tlsVerified:true,tlsStatus,url:page.url(),title:await page.title(),inputs:await page.locator('input').evaluateAll(es=>es.map(e=>({type:e.type,name:e.name,id:e.id,placeholder:e.placeholder}))),buttons:await page.getByRole('button').allTextContents(),text:(await page.locator('body').innerText()).slice(0,1800),browserErrors},null,2));
      await page.screenshot({path:path.join(privateDir,'dashboard-inspect.png')});
      return;
    }
    if(await page.locator('input[type="password"]').count()) {
      await page.locator('input[type="text"]').first().fill('admin');
      await page.locator('input[type="password"]').fill(env.INDEXER_PASSWORD);
      console.log(JSON.stringify({loginFormButtons:await page.getByRole('button').allTextContents(),loginURL:page.url()}));
      await page.locator('input[type="password"]').press('Enter');
      await page.waitForURL(url=>!/\/login\/?$/.test(url.pathname),{timeout:60000});
    }
    await context.storageState({path:statePath});
    const imported = await page.request.post(target+'/api/saved_objects/_import?overwrite=true',{headers:{'osd-xsrf':'true'},multipart:{file:{name:'dashboards.ndjson',mimeType:'application/ndjson',buffer:fs.readFileSync(path.join(root,'monitoring/dashboards.ndjson'))}}});
    const importResult = await imported.json();
    fs.writeFileSync(path.join(privateDir,'dashboard-import.json'),JSON.stringify(importResult,null,2));
    if(!imported.ok() || importResult.success === false) throw new Error('Dashboard import failed; inspect private import result');
    const metrics = JSON.parse(fs.readFileSync(path.join(root,'evidence/monitoring/metrics.json')));
    const from = new Date(new Date(metrics.first_ingestion).getTime()-1000).toISOString();
    const to = new Date(new Date(metrics.last_ingestion).getTime()+1000).toISOString();
    const globalState = encodeURIComponent(`(time:(from:'${from}',to:'${to}'))`);
    await page.goto(target+'/app/dashboards#/view/soc-lab-triage?_g='+globalState,{waitUntil:'domcontentloaded',timeout:60000});
    await page.waitForTimeout(4000);
    if(mode === 'dashboard-inspect') {
      console.log(JSON.stringify({url:page.url(),title:await page.title(),text:(await page.locator('body').innerText()).slice(0,7000),browserErrors},null,2));
      await page.screenshot({path:path.join(privateDir,'dashboard-render-inspect.png'),fullPage:true});
      return;
    }
    await page.getByText('Alerts by rule',{exact:false}).first().waitFor({timeout:60000});
    await page.waitForTimeout(4000);
    await page.screenshot({path:path.join(root,'evidence/monitoring/dashboard-overview.png'),fullPage:true});
    fs.writeFileSync(path.join(privateDir,'dashboard-visible.txt'),await page.locator('body').innerText());
    console.log(JSON.stringify({tlsVerified:true,imported:importResult.successCount,dashboardTitle:await page.title(),dashboardText:(await page.locator('body').innerText()).slice(-5000)},null,2));
    const appState = encodeURIComponent("(columns:!(agent.name,rule.id,data.win.system.eventID,data.win.eventdata.targetUserName,data.win.eventdata.targetDomainName),index:soc-lab-alerts,query:(language:kuery,query:'rule.id:110102'))");
    await page.goto(target+'/app/discover#/?_a='+appState+'&_g='+globalState,{waitUntil:'domcontentloaded',timeout:60000});
    await page.waitForTimeout(4000);
    console.log(JSON.stringify({discoverButtons:await page.getByRole('button').allTextContents(),discoverText:(await page.locator('body').innerText()).slice(-3500)},null,2));
    await page.screenshot({path:path.join(root,'evidence/monitoring/dashboard-lockout.png'),fullPage:true});
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
