import {test,expect} from '@playwright/test'
const screens=[['/','overview','Network overview'],['/benchmark','benchmark','DNS Benchmark'],['/providers','providers','DNS Providers'],['/inspector','inspector','DNS Inspector'],['/connectivity','connectivity','Connectivity'],['/tls','tls','TLS Inspector'],['/routes','routes','Route Analyzer'],['/diagnostics','diagnostics','Smart Diagnostics'],['/monitoring','monitoring','Monitoring'],['/history','history','История'],['/agents','agents','Agents'],['/integrations','integrations','Integrations']]
const sizes=[[1536,1024],[1536,864],[768,1024],[390,844],[320,800]]
test('Obsidian responsive matrix',async({page},info)=>{
 test.setTimeout(240000)
 await page.goto('/')
 await page.getByLabel('Пароль').waitFor()
 for(const [width,height] of sizes){
  await page.setViewportSize({width,height})
  await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
  await page.screenshot({path:info.outputPath(width+'x'+height,'login.png'),fullPage:true,animations:'disabled'})
 }
 await page.getByLabel('Пароль').fill(process.env.NDC_TEST_PASSWORD!)
 await page.getByRole('button',{name:'Войти',exact:true}).click()
 await expect(page.getByRole('heading',{name:'Network overview'})).toBeVisible()
 for(const [width,height] of sizes){
  await page.setViewportSize({width,height})
  if(width<=800){
   await page.getByRole('button',{name:'Открыть меню'}).click()
   await expect(page.getByRole('navigation',{name:'Навигация'})).toBeVisible()
   await page.getByRole('link',{name:'DNS Benchmark',exact:true}).click()
   await expect(page.getByRole('navigation',{name:'Навигация'})).toBeHidden()
  }
  for(const [path,name,title] of screens){
   await page.goto('/#'+path)
   await expect(page.locator('main h1')).toHaveText(title)
   await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
   await page.screenshot({path:info.outputPath(width+'x'+height,name+'.png'),fullPage:true,animations:'disabled'})
  }
 }
 // Populated deterministic fixtures are separate from initial-state captures.
 const endpoints=['https://cloudflare-dns.com/dns-query','https://dns.google/dns-query','udp://9.9.9.9']
 const rows=endpoints.map((endpoint,i)=>({endpoint,ip:['1.1.1.1','8.8.8.8','9.9.9.9'][i],mode:'cold',family:'ipv4',engine:'python-dns02',protocols:[i===2?'udp':'h2'],count:10,requested_count:10,ok:10,mean:8+i*4,p50:7+i*4,p95:10+i*4,p99:12+i*4,jitter:1.2,error:''}))
 await page.route('**/api/defaults',r=>r.fulfill({json:endpoints}))
 await page.route('**/api/status',r=>r.fulfill({json:{running:false,done:3,total:3,results:rows}}))
 await page.route('**/api/history',r=>r.fulfill({json:[{time:1764000000,results:rows},{time:1763900000,results:rows.map(x=>({...x,p95:x.p95+3}))}]}))
 await page.route('**/api/v1/dns/inspect',r=>r.fulfill({json:{name:'example.com.',qtype:'AAAA',comparable:1,groups:1,agreement:null,note:'fixture',results:[{endpoint:endpoints[0],ip:'1.1.1.1',bootstrap_ms:2,duration_ms:8.42,protocol:'h2',peer_ip:'1.1.1.1',error:null,rcode:'NOERROR',flags:['QR','RD','RA','AD'],edns:{version:0,payload:1232},dnssec:{requested_do:true,response_do:false,ad:true,cd:false,independently_validated:false},answer:[{name:'example.com.',type:'AAAA',class:'IN',ttl:300,values:['2001:db8:1234:5678:abcd:ef01:2345:6789']}],authority:[],additional:[],cname_chain:[],fallback:false,outcome:'answer',comparison_group:1}]}}))
 await page.reload()
 for(const [width,height] of [[1536,1024],[390,844],[320,800]]){
  await page.setViewportSize({width,height})
  const capture=async(name:string)=>{
   await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
   await page.screenshot({path:info.outputPath('populated-fixtures',width+'x'+height,name+'.png'),fullPage:true,animations:'disabled'})
  }
  await page.goto('/#/providers')
  await expect(page.locator('main h1')).toHaveText('DNS Providers')
  await page.getByRole('checkbox',{name:'Выбрать '+endpoints[0],exact:true}).check()
  await page.getByRole('checkbox',{name:'Выбрать '+endpoints[1],exact:true}).check()
  await capture('providers')
  await page.getByRole('button',{name:'Подготовить тест · 2'}).click()
  await expect(page.locator('#endpoints')).toHaveValue(endpoints.slice(0,2).join('\n'))
  await expect(page.getByRole('heading',{name:'Результаты',exact:true})).toBeVisible()
  await capture('benchmark')
  await page.goto('/#/history')
  await expect(page.getByRole('heading',{name:'P95 trend',exact:true})).toBeVisible()
  await expect(page.getByRole('img',{name:'P95 по порядку сохранённых запусков'})).toBeVisible()
  await capture('history')
  await page.goto('/#/inspector')
  await page.getByLabel('Тип записи').selectOption('AAAA')
  await page.getByRole('button',{name:'Проверить DNS'}).click()
  await expect(page.getByText('2001:db8:1234:5678:abcd:ef01:2345:6789',{exact:true})).toBeVisible()
  await capture('inspector')
  await page.getByRole('button',{name:'Raw response',exact:true}).click()
  await expect(page.locator('.dns-result pre')).toContainText('2001:db8:1234:5678:abcd:ef01:2345:6789')
 }

})
