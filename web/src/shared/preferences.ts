export type Appearance={density:'standard'|'compact';decoration:boolean}
const key='ndc.appearance'
export function readAppearance():Appearance{try{const v=JSON.parse(localStorage.getItem(key)??'null');return {density:v?.density==='compact'?'compact':'standard',decoration:v?.decoration!==false}}catch{return {density:'standard',decoration:true}}}
export function applyAppearance(v:Appearance){document.documentElement.dataset.density=v.density;document.documentElement.dataset.decoration=v.decoration?'on':'off'}
export function saveAppearance(v:Appearance){localStorage.setItem(key,JSON.stringify(v));applyAppearance(v)}
