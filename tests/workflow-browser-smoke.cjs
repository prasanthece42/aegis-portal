// Isolated demo browser test with intercepted review responses; no live credentials.
const {chromium,expect}=require(process.env.PLAYWRIGHT_MODULE||'@playwright/test');
const fs=require('node:fs');
(async()=>{
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(process.env.AEGIS_PREVIEW_URL||'http://127.0.0.1:8017',{waitUntil:'networkidle'});
  await expect(page.locator('#mode-banner')).toContainText('LOCAL DEMO');
  await page.getByRole('button',{name:/Enter local demo/}).click();
  const overview=await page.evaluate(async()=>await(await fetch('/api/v1/platform/overview')).json());
  overview.mode='live'; // Layout fixture only; the server/banner remain an explicit local demo.
  overview.reviews=[{repository:'Platform',repository_key:'platform',number:7,title:'Review test app',branch:'main',draft:false,ci_state:'running'}];overview.review_total=1;
  await page.route('**/api/v1/platform/overview',r=>r.fulfill({json:overview}));
  const view={repository:'platform',number:7,title:'Review test app',head:'a'.repeat(40),base:'b'.repeat(40),branch:'main',state:'open',merged:false,can_review:true,can_merge:true,review_token:'fixture-not-a-live-token',reviews:[],files:[{path:'app.py',status:'modified',binary:false,diff:'-old\n+<img src=x onerror="window.reviewXss=true">\n'}]};
  const writes=[];
  await page.route('**/api/v1/platform/reviews/platform/7',async route=>{
   if(route.request().method()==='GET')return route.fulfill({json:view});
   const body=route.request().postDataJSON();writes.push(body);
   if(body.action==='merge')return route.fulfill({status:409,json:{error:{message:'Merge is blocked by required checks.'}}});
   return route.fulfill({json:{status:'approved',reviewer_user_id:'1',review_id:'1'}});
  });
  await page.locator('#nav-platform').click();await page.getByRole('tab',{name:'Reviews',exact:true}).click();
  await page.getByRole('button',{name:'Review changes',exact:true}).click();
  await expect(page.locator('#workflow-review')).toBeVisible();
  await expect(page.locator('#workflow-files')).toContainText('<img');
  if(await page.evaluate(()=>Boolean(window.reviewXss)))throw new Error('Diff executed as HTML');
  await page.locator('#workflow-approve').click();
  if(writes.length)throw new Error('Approval sent without acknowledgement');
  await page.locator('#workflow-ack').check();await page.locator('#workflow-approve').click();
  await expect(page.locator('#workflow-result')).toContainText('Review recorded as demo-developer');
  if(writes[0].action!=='approve'||writes[0].acknowledge!==true||!writes[0].operation_key)throw new Error('Unbound review submission');
  await page.locator('#workflow-ack').check();await page.locator('#workflow-merge').click();
  await expect(page.locator('#error')).toContainText('required checks');
  await page.setViewportSize({width:375,height:812});
  if(!(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)))throw new Error('Mobile review overflows');
  fs.mkdirSync('.local/unified-qa',{recursive:true});
  await page.screenshot({path:'.local/unified-qa/review-mobile.png',fullPage:true});
  if(errors.length)throw new Error(JSON.stringify(errors));
  console.log(JSON.stringify({inPortalReview:'passed',explicitAcknowledgement:'passed',humanDecisionPayload:'passed',blockedMerge:'visible',escapedDiff:'passed',mobile:'passed',javascriptErrors:errors,mode:'isolated-demo-with-intercepted-fixtures'}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
