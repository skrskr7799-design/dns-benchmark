import {test,expect} from '@playwright/test'
const screens=[['/','overview','Network overview'],['/benchmark','benchmark','DNS Benchmark'],['/providers','providers','DNS Providers'],['/inspector','inspector','DNS Inspector'],['/connectivity','connectivity','Connectivity'],['/tls','tls','TLS Inspector'],['/routes','routes','Route Analyzer'],['/diagnostics','diagnostics','Smart Diagnostics'],['/monitoring','monitoring','Monitoring'],['/history','history','История'],['/agents','agents','Agents'],['/integrations','integrations','Integrations']]
const sizes=[[1536,1024],[1536,864],[768,1024],[390,844],[320,800]]
test('Obsidian responsive matrix',async({page},info)=>{
 test.setTimeout(180000)
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
})
