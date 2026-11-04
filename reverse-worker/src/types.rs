use serde::{Serialize,Deserialize};
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase")]
pub struct Finding {pub id:String,pub level:String,pub title:String,pub description:String,pub location:String,pub line:Option<usize>,pub excerpt:String,pub remediation:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Metric {pub label:String,pub value:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Indicator {pub kind:String,pub value:String,pub source:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Detail {pub label:String,pub value:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase")]
pub struct AnalysisReport {pub kind:String,pub engine:String,pub title:String,pub summary:String,pub metrics:Vec<Metric>,pub findings:Vec<Finding>,pub indicators:Vec<Indicator>,pub details:Vec<Detail>,pub warnings:Vec<String>,#[serde(default,skip_serializing_if="Option::is_none")] pub webshell:Option<crate::webshell_schema::WebshellAnalysis>}
pub fn report(kind:&str,title:&str)->AnalysisReport {AnalysisReport{kind:kind.into(),engine:"J4team isolated-static/0.6.6".into(),title:title.into(),summary:String::new(),metrics:vec![],findings:vec![],indicators:vec![],details:vec![],warnings:vec![],webshell:None}}
pub fn metric(label:&str,value:impl ToString)->Metric {Metric{label:label.into(),value:value.to_string()}}
pub fn detail(label:&str,value:impl ToString)->Detail {Detail{label:label.into(),value:value.to_string()}}
pub fn cut(s:&str,max:usize)->String {s.chars().take(max).collect()}
pub fn finding(level:&str,title:&str,description:&str,location:String,line:Option<usize>,excerpt:&str,remediation:&str)->Finding {Finding{id:uuid::Uuid::new_v4().to_string(),level:level.into(),title:title.into(),description:description.into(),location,line,excerpt:cut(excerpt,2000),remediation:remediation.into()}}
