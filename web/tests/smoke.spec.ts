import {test,expect,type Page} from '@playwright/test'
async function login(page:Page){await page.goto('/');await page.getByLabel('Пароль').fill(process.env.NDC_TEST_PASSWORD!);await page.getByRole('button',{name:'Войти',exact:true}).click();await expect(page.getByRole('heading',{name:'Network overview'})).toBeVisible()}

test('real API and responsive shell',async({page})=>{
 await login(page)
 await expect(page.getByRole('heading',{name:'Network overview'})).toBeVisible()
 await page.getByRole('link',{name:'DNS Benchmark'}).click()
 await expect(page.locator('#endpoints')).toHaveValue(/https:\/\//)
 await expect(page.getByRole('button',{name:'Запустить тест'})).toBeEnabled()
 await page.setViewportSize({width:390,height:844})
 expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
 await page.getByRole('link',{name:'История',exact:true}).click()
 await expect(page.getByRole('heading',{name:'История'})).toBeVisible()
 await expect(page.getByText('История пока пуста.')).toBeVisible()
})
test('start, progress, table and export against controlled API fixture',async({page})=>{
 const row={endpoint:'udp://127.0.0.1:15353',ok:2,count:2,mean:10,p50:9,p95:11,p99:11,jitter:1,mode:'cold',ip:'127.0.0.1',error:''}
 let started=false
 await page.route('**/api/status',r=>r.fulfill({json:{running:false,done:started?1:0,total:started?1:0,results:started?[row]:[]}}))
 await page.route('**/api/run',async r=>{expect(r.request().postDataJSON()).toMatchObject({endpoints:[row.endpoint],count:2,mode:'cold'});started=true;await r.fulfill({json:{started:true}})})
 await login(page)
 await page.getByRole('link',{name:'DNS Benchmark'}).click()
 await page.locator('#endpoints').fill(row.endpoint)
 await page.getByLabel('Запросов').fill('2')
 await page.getByRole('button',{name:'Запустить тест'}).click()
 await expect(page.getByRole('cell',{name:'2/2'})).toBeVisible()
 const download=page.waitForEvent('download')
 await page.getByRole('button',{name:'Экспорт JSON'}).click()
 expect((await download).suggestedFilename()).toBe('dns-results.json')
})

test('inspector navigation, form and deterministic rendering',async({page})=>{
 await login(page)
 await page.route('**/api/v1/dns/inspect',async route=>{
   const body=route.request().postDataJSON()
   expect(body.qtype).toBe('AAAA')
   expect(body.dnssec).toBe(true)
   await route.fulfill({json:{name:'example.com.',qtype:'AAAA',comparable:1,groups:1,agreement:null,note:'',results:[{endpoint:'udp://127.0.0.1',ip:'127.0.0.1',bootstrap_ms:1,duration_ms:2,protocol:'udp',peer_ip:null,error:null,rcode:'NOERROR',flags:['QR','AD'],edns:{version:0,payload:1232},dnssec:{requested_do:true,response_do:true,ad:true,cd:false,independently_validated:false},answer:[{name:'example.com.',type:'AAAA',class:'IN',ttl:42,values:['2001:db8::1']}],authority:[],additional:[],cname_chain:[],fallback:false,outcome:'answer',comparison_group:1}]}})
 })
 await page.getByRole('link',{name:'DNS Inspector'}).click()
 await page.getByLabel('Тип записи').selectOption('AAAA')
 await page.getByLabel('DNSSEC / DO').check()
 await page.getByRole('button',{name:'Проверить DNS'}).click()
 await expect(page.getByText('2001:db8::1',{exact:true})).toBeVisible()
 await expect(page.getByText('Недостаточно ответов для сравнения',{exact:false})).toBeVisible()
 await page.setViewportSize({width:390,height:844})
 expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
})
