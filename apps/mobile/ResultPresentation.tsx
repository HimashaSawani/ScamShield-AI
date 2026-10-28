import React from 'react';
import {StyleSheet, Text, View} from 'react-native';

export type Evidence={code:string;description:string;quote:string;weight:number;start:number;end:number};
export type UrlDetail={url:string;hostname:string|null;registrable_domain:string|null;registrable_domain_note?:string;subdomain:string|null;user_information:string|null;user_information_present:boolean;user_information_note?:string;checks:{completed:string[];failed:string[];unavailable:string[]};psl:{library:string;version:string}};

export function UrlObservations({details}:{details:UrlDetail[]}){
  return <View>{details.map((detail,index)=><View key={index} style={styles.urlCard}>
    <Text style={styles.title}>URL destination details</Text>
    <Text style={styles.plainUrl}>{detail.url}</Text>
    <Text style={styles.label}>ACTUAL HOSTNAME</Text><Text style={styles.urlField}>{detail.hostname||'Unavailable: URL parsing failed'}</Text>
    <Text style={styles.label}>REGISTRABLE DOMAIN (PSL)</Text><Text style={styles.urlField}>{detail.registrable_domain||detail.registrable_domain_note||'Unavailable'}</Text>
    <Text style={styles.label}>SUBDOMAIN</Text><Text style={styles.urlField}>{detail.subdomain||'None identified / unavailable'}</Text>
    <Text style={styles.label}>USER INFORMATION BEFORE @</Text><Text style={styles.urlField}>{detail.user_information_present?detail.user_information:'None'}</Text>
    {detail.user_information_note&&<Text style={styles.urlField}>{detail.user_information_note}</Text>}
    <Text style={styles.urlField}>Completed: {detail.checks.completed.join(', ')||'None'}</Text>
    <Text style={styles.urlField}>Failed: {detail.checks.failed.join(', ')||'None recorded'}</Text>
    <Text style={styles.urlField}>Unavailable: {detail.checks.unavailable.join(', ')||'None recorded'}</Text>
    <Text style={styles.weight}>{detail.psl.library} {detail.psl.version} · Offline PSL snapshot. Links are plain text; no destination was opened. HTTPS is not proof of safety.</Text>
  </View>)}</View>;
}

export function ResultHeader({assessment,status}:{assessment?:string;status:string}){
  const palette:Record<string,{color:string;backgroundColor:string}>={High:{color:'#b24a40',backgroundColor:'#fcece9'},Medium:{color:'#a07c31',backgroundColor:'#fbf3e0'},Low:{color:'#4e815d',backgroundColor:'#edf5ed'},Inconclusive:{color:'#68768d',backgroundColor:'#edf0f6'}};
  return <View style={styles.states}>
    <View><Text style={styles.label}>ASSESSMENT</Text><Text style={[styles.badge,palette[assessment||'']||palette.Inconclusive]}>{assessment||'Pending'}</Text></View>
    <View><Text style={styles.label}>PROCESSING</Text><Text style={styles.status}>{status.replaceAll('_',' ')}</Text></View>
  </View>;
}

export function EvidenceItem({item}:{item:Evidence}){
  return <View style={styles.evidence}>
    <Text style={styles.title}>{item.description}</Text>
    <Text style={styles.quote}>{item.quote}</Text>
    <Text style={styles.weight}>Indicator weight: +{item.weight} · Counted once per signal</Text>
  </View>;
}

export function HighlightedMessage({text,evidence}:{text:string;evidence:Evidence[]}){
  const chars=Array.from(text),parts:React.ReactNode[]=[];
  let position=0;
  for(const item of [...evidence].sort((a,b)=>a.start-b.start)){
    if(!Number.isInteger(item.start)||item.start<position||item.end<=item.start)continue;
    parts.push(chars.slice(position,item.start).join(''));
    parts.push(<Text key={`${item.start}-${item.end}`} style={styles.highlight}>{chars.slice(item.start,item.end).join('')}</Text>);
    position=item.end;
  }
  parts.push(chars.slice(position).join(''));
  return <Text style={styles.message}>{parts}</Text>;
}

const styles=StyleSheet.create({
  urlCard:{maxWidth:'100%',minWidth:0,borderWidth:1,borderColor:'#e3e9df',borderRadius:8,padding:14,marginVertical:14},
  plainUrl:{flexShrink:1,color:'#4a634f',backgroundColor:'#f5f7f1',lineHeight:22,padding:10,marginBottom:16},
  urlField:{flexShrink:1,color:'#65776c',lineHeight:21,marginBottom:14},
  states:{flexDirection:'row',flexWrap:'wrap',gap:24,marginVertical:16,borderBottomWidth:1,borderColor:'#e3e9df',paddingBottom:18},
  label:{fontSize:10,letterSpacing:1,color:'#6c8271',marginBottom:8},
  badge:{fontSize:18,fontWeight:'700',color:'#214b38',backgroundColor:'#edf3e9',paddingHorizontal:10,paddingVertical:6,borderRadius:6},
  status:{fontSize:13,color:'#65776c',paddingVertical:9,textTransform:'capitalize'},
  evidence:{borderBottomWidth:1,borderColor:'#e3e9df',paddingVertical:18},
  title:{fontSize:14,fontWeight:'600',color:'#264a37',marginBottom:10},
  quote:{fontSize:14,lineHeight:23,color:'#5d572d',backgroundColor:'#faf4d8',padding:12,borderRadius:6},
  weight:{fontSize:11,color:'#77867b',marginTop:12,lineHeight:18},
  message:{backgroundColor:'#f5f7f1',padding:16,lineHeight:24,color:'#4a634f',marginVertical:12},
  highlight:{backgroundColor:'#f4e6a2',color:'#4a4926'},
});
