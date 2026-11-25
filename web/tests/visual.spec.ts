import {test,expect} from '@playwright/test'
const screens=[['/','overview'],['/benchmark','benchmark'],['/inspector','inspector'],['/connectivity','connectivity'],['/tls','tls'],['/routes','routes'],['/diagnostics','diagnostics'],['/monitoring','monitoring'],['/history','history'],['/agents','agents'],['/integrations','integrations']]
for(const [width,height] of [[1536,1024],[1536,864],[768,1024],[390,844],[320,800]]){
 test('Obsidian responsive '+width+'x'+height,async({page},info)=>{
  test.setTimeout(90000)
  await page.setViewportSize({width,height})
  await page.goto('/')
  await page.getByLabel('Пароль').waitFor()
  await page.screenshot({path:info.outputPath('login.png'),fullPage:true,animations:'disabled'})
  await page.getByLabel('Пароль').fill(process.env.NDC_TEST_PASSWORD!)
  await page.getByRole('button',{name:'Войти',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Network overview'})).toBeVisible()
  if(width<=800){
   const menu=page.getByRole('button',{name:'Открыть меню'})
   await menu.click()
   await expect(page.getByRole('navigation',{name:'Навигация'})).toBeVisible()
   await page.getByRole('link',{name:'DNS Benchmark',exact:true}).click()
   await expect(page.getByRole('navigation',{name:'Навигация'})).toBeHidden()
  }
  for(const [path,name] of screens){
   await page.goto('/#'+path)
   await expect(page.locator('main h1')).toBeVisible()
   await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
   // Captures empty/initial state from actual controller, not generated imagery.
   await page.screenshot({path:info.outputPath(name+'.png'),fullPage:true,animations:'disabled'})
  }
 })
}
