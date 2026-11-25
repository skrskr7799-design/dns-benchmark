import {test,expect} from '@playwright/test'
test('real API and responsive shell',async({page})=>{
 await page.goto('/')
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
 await page.goto('/#/benchmark')
 await page.locator('#endpoints').fill(row.endpoint)
 await page.getByLabel('Запросов').fill('2')
 await page.getByRole('button',{name:'Запустить тест'}).click()
 await expect(page.getByRole('cell',{name:'2/2'})).toBeVisible()
 const download=page.waitForEvent('download')
 await page.getByRole('button',{name:'Экспорт JSON'}).click()
 expect((await download).suggestedFilename()).toBe('dns-results.json')
})
