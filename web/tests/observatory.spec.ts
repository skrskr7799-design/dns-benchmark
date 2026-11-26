import {test,expect} from '@playwright/test'
const id='a'.repeat(32),eid='b'.repeat(64),now=1764000000
const monitor={id,name:'Local TCP fixture',kind:'tcp',enabled:true,interval_seconds:60,state:'healthy',last_at:now-60}
const points=Array.from({length:18},(_,i)=>({at:now-1440+i*60,received_at:now-1440+i*60+1,evidence_id:i.toString(16).padStart(64,'0'),outcome:'success',latency_ms:i===15?null:i===12||i===13?60:10,baseline_ms:i>=12&&i<15?10:null,mad_ms:i>=12?0:null,threshold_ms:i>=12&&i<15?15:null,baseline_samples:Math.min(i+1,12),state:i===13?'anomaly':'learning',gap_before:i===16,boundary_before:i===16,comparison_changed:false}))
const journal=[{seq:1,at:points[13].at,type:'anomaly.detected',reason:'consecutive_high_latency',evidence_id:eid,rule_version:'observatory-v1',baseline_ms:10,threshold_ms:15,latency_ms:60},{seq:2,at:points[15].at,type:'monitor.paused',reason:'owner_toggle',evidence_id:null,rule_version:'observatory-v1',baseline_ms:null,threshold_ms:null,latency_ms:null},{seq:3,at:points[16].at,type:'monitor.resumed',reason:'owner_toggle',evidence_id:null,rule_version:'observatory-v1',baseline_ms:null,threshold_ms:null,latency_ms:null}]
const fixture={methodology:'observatory-v1',monitor:{...monitor,source_state:'healthy'},window:{since:now-1500,before:now,time_basis:'observed_at_check_commit'},counts:{total:18,success:18,degraded:0,failure:0,unknown:0,known:18},observed_healthy_ratio:1,gap_count:1,last_point_state:'learning',current_state:'learning',stale_at_window_end:false,points,policy:{baseline_minimum:12,baseline_maximum:30,baseline_max_age_seconds:86400,confirmation_checks:2,recovery_checks:2,gap_seconds:180,threshold:'fixture'},persistent:{tracking_since:now-1500,rule_version:'observatory-v1',state_at_read:'learning',active_at_read:false,last_check_at:now-60,baseline_samples_at_read:2,journal,prior_boundary:null,journal_max_entries:2000,journal_retention_days:30,historical_coverage_verified:false},coverage:{retained_usage_at_read:{rows:20,bytes:1000,evicted:0,last_evicted_at:null},producer_status_at_response:{pending:0,dropped:0,dropped_transitions:0,max_pending:10000},stream_error:null,complete_window_verified:false},limitations:[]}
test('Observatory route, pause gaps, journal and responsive states',async({page},info)=>{
 test.setTimeout(120000)
 await page.goto('/')
 await page.getByLabel('Пароль').fill(process.env.NDC_TEST_PASSWORD!)
 await page.getByRole('button',{name:'Войти',exact:true}).click()
 await expect(page.getByRole('heading',{name:'Network overview'})).toBeVisible()
 let empty=true,fail=false,noPoints=false
 await page.route('**/api/v1/intelligence/observatory/monitors',r=>r.fulfill({json:empty?[]:[monitor]}))
 await page.route('**/api/v1/intelligence/observatory/monitors/*?*',r=>fail?r.fulfill({status:422,json:{detail:'Narrow window'}}):r.fulfill({json:noPoints?{...fixture,points:[],counts:{total:0,success:0,degraded:0,failure:0,unknown:0,known:0},observed_healthy_ratio:null}:fixture}))
 await page.route('**/api/v1/intelligence/observations/'+eid,r=>r.fulfill({json:{id:eid,seq:1,received_at:now,record:{observed_at:now,vantage_id:'controller',measurements:[{name:'latency',unit:'ms',value:60}]}}}))
 await page.goto('/#/observatory')
 await expect(page.getByRole('heading',{name:'Нет настроенных мониторов'})).toBeVisible()
 empty=false
 await page.getByRole('button',{name:'Обновить',exact:true}).click()
 await expect(page.getByRole('heading',{name:'Задержка и базовая линия'})).toBeVisible()
 await expect(page.locator('.obs-pause-band')).toHaveCount(1)
 expect((await page.locator('[data-series="latency"]').getAttribute('d'))!.match(/M/g)!.length).toBeGreaterThan(1)
 await page.getByLabel('Измерение',{exact:true}).selectOption(points[13].evidence_id)
 await expect(page.locator('.obs-point-facts')).toContainText('60.0 мс')
 await page.getByRole('button',{name:/Аномалия обнаружена/}).click()
 await page.getByRole('button',{name:'Наблюдение события'}).click()
 await expect(page.getByLabel('Данные наблюдения')).toContainText('60')
 for(const [width,height] of [[1536,1024],[1024,768],[768,1024],[390,844],[320,800]]){
  await page.setViewportSize({width,height})
  await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(width)
  await page.screenshot({path:info.outputPath('observatory-fixture',width+'x'+height+'.png'),fullPage:true,animations:'disabled'})
 }
 noPoints=true
 await page.getByLabel('Период',{exact:true}).selectOption('1')
 await expect(page.getByRole('heading',{name:'Нет наблюдений в периоде'})).toBeVisible()
 fail=true
 await page.getByLabel('Период',{exact:true}).selectOption('24')
 await expect(page.getByRole('heading',{name:'Анализ недоступен'})).toBeVisible()
 fail=false;noPoints=false
 await page.getByRole('button',{name:'Повторить',exact:true}).click()
 await expect(page.locator('.obs-chart')).toBeVisible()
})
