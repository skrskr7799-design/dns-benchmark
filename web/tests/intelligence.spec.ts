import {test,expect} from '@playwright/test'
const id='a'.repeat(64), second='b'.repeat(64), third='c'.repeat(64)
const endpoint='https://resolver.example.test/dns-query'
const weights={balanced:{reliability:60,p50:15,p95:20,jitter:5},speed:{reliability:40,p50:25,p95:30,jitter:5},reliability:{reliability:80,p50:5,p95:10,jitter:5}}
function fixture(preset:keyof typeof weights='balanced',empty=false){
 const w=weights[preset],components=Object.fromEntries(Object.entries(w).map(([k,v])=>[k,{weight:v,normalized:90,contribution:v*.9}]))
 const target=(target_id:string,endpoint:string,rank:number|null)=>({target_id,endpoint,bootstrap_ip:'192.0.2.1',series:3,attempted:30,successful:30,successful_series:3,latency_series:3,example_evidence_id:id,observed_success_ratio:1,median_series_ms:{p50:8,p95:16,jitter:3},score:rank===null?null:rank===1?90:80,rank,components:rank===null?null:components,unranked_reasons:rank===null?['insufficient_attempts']:[]})
 return {methodology:'dns-intelligence-v1',preset,weights:w,latency_reference_ms:{p50:20,p95:50,jitter:10},minimum:{matched_runs:3,attempted_queries:30,successful_queries:20,recommendation_success_ratio:.95},records_read:empty?0:9,runs_considered:empty?0:3,excluded_run_groups:empty?{}:{ineligible_or_mismatched_series:1},groups:empty?[]:[{group_id:id,mode:'cold',protocol:'h2',family:'ipv4',profile_revision:id,matched_runs:3,first_received_at:1764000000,last_received_at:1764000300,targets:[target(id,endpoint,1),target(second,'https://second.example.test/dns-query',2),target(third,'https://unranked.example.test/dns-query',null)],recommended_target_id:id,recommendation_blockers:[]}],coverage:{producer_pending:0,stream_error:null,complete_window_verified:false,time_basis:'received_at',since:1763900000,before:1764000300,retained_usage_at_read:{rows:9,bytes:1000,evicted:0,last_evicted_at:null}},limitations:['series_percentiles_not_pooled_percentiles','no_privacy_security_or_filtering_score']}
}
test('DNS Intelligence real route and deterministic UI states',async({page},info)=>{
 test.setTimeout(120000)
 await page.goto('/')
 await page.getByLabel('Пароль').fill(process.env.NDC_TEST_PASSWORD!)
 await page.getByRole('button',{name:'Войти',exact:true}).click()
 await expect(page.getByRole('heading',{name:'Network overview'})).toBeVisible()
 let empty=true,fail=false
 await page.route('**/api/v1/intelligence/dns/ranking?*',r=>{
  const p=new URL(r.request().url()).searchParams.get('preset') as keyof typeof weights
  return fail?r.fulfill({status:422,json:{detail:'Narrow the ranking time range or profile'}}):r.fulfill({json:fixture(p,empty)})
 })
 await page.route('**/api/v1/intelligence/observations/'+id,r=>r.fulfill({json:{id,seq:1,received_at:1764000000,record:{source_kind:'benchmark',source_id:'fixture',source_revision:1,source_part:'0',run_id:'fixture-run',vantage_id:'controller',observed_at:1764000000,outcome:'success',provenance:'controller',protocol:'h2',family:'ipv4',measurements:[{name:'p95',unit:'ms',value:16}],limitations:['result_commit_time']}}}))
 await page.goto('/#/intelligence')
 await expect(page.getByRole('heading',{name:'Недостаточно сопоставимых данных'})).toBeVisible()
 await expect(page.getByRole('link',{name:'Открыть DNS Benchmark'})).toHaveAttribute('href','/#/benchmark')
 empty=false
 await page.getByRole('button',{name:'Обновить анализ'}).click()
 await expect(page.getByRole('heading',{name:'Рекомендуемый DNS'})).toBeVisible()
 await expect(page.getByRole('heading',{name:'Рейтинг DNS'})).toBeVisible()
 await page.getByRole('button',{name:'Скорость',exact:true}).click()
 await expect(page.getByRole('button',{name:'Скорость',exact:true})).toHaveAttribute('aria-pressed','true')
 await expect(page.locator('.intel-legend')).toContainText('40%')
 await page.getByRole('button',{name:'Разбор https://unranked.example.test/dns-query'}).click()
 await expect(page.getByText('Оценка недоступна',{exact:true})).toBeVisible()
 await page.getByRole('button',{name:'Разбор '+endpoint}).click()
 await page.getByRole('button',{name:'Исходное наблюдение'}).click()
 await expect(page.getByRole('region',{name:'Исходное наблюдение'})).toContainText('fixture-run')
 await page.getByLabel('Режим',{exact:true}).selectOption('warm')
 await expect(page.getByRole('heading',{name:'Нет групп по выбранным фильтрам'})).toBeVisible()
 await page.getByLabel('Режим',{exact:true}).selectOption('all')
 for(const [width,height] of [[1536,1024],[1024,768],[768,1024],[390,844],[320,800]]){
  await page.setViewportSize({width,height})
  await expect(page.getByRole('heading',{name:'Рейтинг DNS'})).toBeVisible()
  await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
  await page.screenshot({path:info.outputPath('intelligence-fixture',width+'x'+height+'.png'),fullPage:true,animations:'disabled'})
 }
 fail=true
 await page.getByRole('button',{name:'Обновить анализ'}).click()
 await expect(page.getByRole('heading',{name:'Анализ недоступен'})).toBeVisible()
 await expect(page.getByRole('heading',{name:'Рекомендуемый DNS'})).toHaveCount(0)
 fail=false
 await page.getByRole('button',{name:'Повторить',exact:true}).click()
 await expect(page.getByRole('heading',{name:'Рекомендуемый DNS'})).toBeVisible()
})
