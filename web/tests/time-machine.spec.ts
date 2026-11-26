import {test,expect} from '@playwright/test'
const id=(n:number)=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0'),now=1764000000
const row=(n:number,scope='dns',config_key='a'.repeat(64))=>({id:id(n),seq:n,label:n===1?'Before':n===2?'After':'Other',captured_at:now+n*60,content_hash:'b'.repeat(64),size:1024,scope,config_key})
test('Time Machine real route and deterministic history comparison',async({page},info)=>{
 test.setTimeout(120000)
 await page.goto('/')
 await page.getByLabel('Пароль').fill(process.env.NDC_TEST_PASSWORD!)
 await page.getByRole('button',{name:'Войти',exact:true}).click()
 await expect(page.getByRole('heading',{name:'Network overview'})).toBeVisible()
 let items:ReturnType<typeof row>[]=[]
 let schedules:any[]=[]
 let fail=false
 const base='**/api/v1/intelligence/time-machine'
 await page.route(base+'/snapshots?*',r=>fail?r.fulfill({status:500,json:{detail:'fixture'}}):r.fulfill({json:{items,next_before:null,usage:{count:items.length,bytes:items.length*1024,max_count:200,max_bytes:4194304}}}))
 await page.route(base+'/snapshots',r=>{
  const body=r.request().postDataJSON();const created={...row(4,'configured_monitors',''),id:body.request_id,label:body.label}
  items=[created,...items];return r.fulfill({status:201,json:{...created,snapshot:{scope:'configured_monitors',monitors:[],methodology:'monitor-snapshot-v1',limitations:[]}}})
 })
 await page.route(base+'/snapshots/*',r=>{
  const key=r.request().url().split('/').at(-1)
  if(r.request().method()==='DELETE'){items=items.filter(x=>x.id!==key);return r.fulfill({status:204})}
  const item=items.find(x=>x.id===key)
  return item?r.fulfill({json:{...item,snapshot:{scope:item.scope,methodology:'probe-snapshot-v1',target:{name:'example.com.'},observation:{rrsets:[{values:['192.0.2.2']}]},limitations:[]}}}):r.fulfill({status:404,json:{detail:'not found'}})
 })
 await page.route(base+'/compare?*',r=>r.fulfill({json:{methodology:'probe-diff-v1',scope:'dns',before_id:id(1),after_id:id(2),changes:[{field:'rrset',key:['example.com.','IN','A'],before:['192.0.2.1'],after:['192.0.2.2'],status:'changed'},{field:'protocol',before:'udp',after:'udp',status:'unchanged'},{field:'rrsets',before:null,after:null,status:'unknown'}],limitations:[]}}))
 await page.route(base+'/schedules',r=>{
  if(r.request().method()==='POST'){const config=r.request().postDataJSON();schedules=[{id:'schedule1',config,enabled:true,running:false,next_at:now+3600,last_at:null,last_status:null,last_error:null,last_snapshot_id:null,runs:0,errors:0}];return r.fulfill({status:201,json:schedules[0]})}
  return r.fulfill({json:schedules})
 })
 await page.route(base+'/schedules/*',r=>{
  if(r.request().method()==='DELETE'){schedules=[];return r.fulfill({status:204})}
  schedules[0].enabled=r.request().postDataJSON().enabled;return r.fulfill({json:schedules[0]})
 })
 await page.goto('/#/time-machine')
 await expect(page.getByRole('heading',{name:'Нет снимков'})).toBeVisible()
 await page.getByLabel('Название снимка').fill('Manual fixture')
 await page.getByRole('button',{name:'Сохранить снимок'}).click()
 await expect(page.getByRole('button',{name:/Manual fixture/})).toBeVisible()
 await page.getByRole('button',{name:/Manual fixture/}).click()
 await page.getByRole('button',{name:'Удалить снимок',exact:true}).click()
 await page.getByRole('button',{name:'Удалить окончательно'}).click()
 await expect(page.getByRole('heading',{name:'Нет снимков'})).toBeVisible()
 items=[row(3,'dns','c'.repeat(64)),row(2),row(1)]
 await page.getByRole('button',{name:'Обновить',exact:true}).click()
 await page.getByLabel('Снимок до').selectOption(id(1))
 await expect(page.getByLabel('Снимок после').locator('option')).toHaveCount(2)
 await page.getByLabel('Снимок после').selectOption(id(2))
 await page.getByRole('button',{name:'Сравнить',exact:true}).click()
 await expect(page.locator('.tm-diff-row')).toHaveCount(2)
 await expect(page.locator('.tm-diff-row').first()).toContainText('192.0.2.2')
 await page.getByLabel('Только изменения и неизвестные').uncheck()
 await expect(page.locator('.tm-diff-row')).toHaveCount(3)
 await page.getByRole('button',{name:/After/}).click()
 await expect(page.locator('.tm-detail')).toContainText('SHA-256')
 await page.getByRole('button',{name:'По расписанию'}).click()
 await page.getByLabel('Название снимка').fill('Scheduled fixture')
 await page.getByRole('button',{name:'Создать расписание'}).click()
 await expect(page.locator('.tm-schedule')).toContainText('Scheduled fixture')
 await page.getByRole('button',{name:'Пауза',exact:true}).click()
 await expect(page.getByRole('button',{name:'Возобновить',exact:true})).toBeVisible()
 await page.getByRole('button',{name:'Возобновить',exact:true}).click()
 await expect(page.getByRole('button',{name:'Пауза',exact:true})).toBeVisible()
 for(const [width,height] of [[1536,1024],[1024,768],[768,1024],[390,844],[320,800]]){
  await page.setViewportSize({width,height})
  await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
  await page.screenshot({path:info.outputPath('time-machine-fixture',width+'x'+height+'.png'),fullPage:true,animations:'disabled'})
 }
 await page.getByRole('button',{name:'Удалить расписание'}).click()
 await page.getByRole('button',{name:'Подтвердить удаление'}).click()
 await expect(page.locator('.tm-schedule')).toHaveCount(0)
 fail=true
 await page.getByRole('button',{name:'Обновить',exact:true}).click()
 await expect(page.getByText('История недоступна.',{exact:false})).toBeVisible()
})
