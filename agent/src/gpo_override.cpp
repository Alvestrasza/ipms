// File Name: gpo_override.cpp
// Version: v0.1.0 | Created: 2026-09-16 | Last Modified: 2026-09-16
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Typed sparse overrides bound to compiled Microsoft setting identities.
#include "ipms/agent/gpo_override.hpp"
#include "ipms/agent/security_gpo_override_content.hpp"
#include <algorithm>
#include <set>

namespace ipms::agent::gpo {
namespace {
[[noreturn]] void invalid(){throw operation_error("gpo_invalid_job");}
const override_component_descriptor& descriptor(const job& j) {
  for(const auto& c:override_components)if(c.baseline_id==j.text("baseline_id")&&c.backup_id==j.text("backup_id")&&
      c.artifact_sha256==j.text("artifact_sha256"))return c;
  invalid();
}
json::object setting(const override_component_descriptor& c,std::string_view id) {
  for(const auto& s:c.settings)if(s.setting_id==id)return json::parse(s.metadata_json).as<json::object>();
  invalid();
}
bool safe_text(std::string_view text,std::size_t maximum) {
  return static_cast<std::size_t>(std::count_if(text.begin(),text.end(),[](unsigned char c){return (c&0xc0)!=0x80;}))<=maximum&&
    std::none_of(text.begin(),text.end(),[](unsigned char c){return c<32||c==127;});
}
bool sid(std::string_view value) {
  if(!value.starts_with("S-1-")||value.size()>184||value.back()=='-')return false;
  unsigned parts{};std::size_t begin=4;
  while(begin<value.size()) {
    const auto end=value.find('-',begin);const auto token=value.substr(begin,end==value.npos?value.size()-begin:end-begin);
    if(token.empty()||(token.size()>1&&token.front()=='0'))return false;
    std::uint64_t number{};const std::uint64_t maximum=parts==0?281474976710655ULL:4294967295ULL;
    for(char c:token){if(c<'0'||c>'9'||number>(maximum-static_cast<unsigned>(c-'0'))/10)return false;number=number*10+static_cast<unsigned>(c-'0');}
    ++parts;if(parts>16)return false;if(end==value.npos)break;begin=end+1;
  }
  return parts>=2;
}
void validate_value(const json::object& d,const json::value& value) {
  if(!d.at("editable").as<bool>()||value==d.at("baseline_value"))invalid();
  const auto& type=d.at("value_type").as<std::string>();
  if(type=="integer") {
    const auto* number=value.get_if<std::int64_t>();
    if(!number||*number<d.at("min").as<std::int64_t>()||*number>d.at("max").as<std::int64_t>())invalid();
  } else if(type=="string") {
    const auto* text=value.get_if<std::string>();
    if(!text||!safe_text(*text,static_cast<std::size_t>(d.at("max_length").as<std::int64_t>())))invalid();
  } else if(type=="string_list") {
    const auto* values=value.get_if<json::array>();
    if(!values||values->size()>static_cast<std::size_t>(d.at("max_items").as<std::int64_t>()))invalid();
    std::set<std::string> unique;
    for(const auto& item:*values) {
      const auto* text=item.get_if<std::string>();
      if(!text||!safe_text(*text,static_cast<std::size_t>(d.at("max_length").as<std::int64_t>()))||
          !unique.insert(*text).second)invalid();
      if(d.at("kind").as<std::string>()=="privilege_right"&&!sid(*text))invalid();
    }
  } else invalid();
  const auto& options=d.at("enum_options").as<json::array>();
  if(!options.empty()&&std::none_of(options.begin(),options.end(),[&](const auto& option){return option.template as<json::object>().at("value")==value;}))invalid();
}
void u16(std::string& result,std::uint32_t value) {
  result.push_back(static_cast<char>(value&255));result.push_back(static_cast<char>((value>>8)&255));
}
void u32(std::string& result,std::uint32_t value) {u16(result,value);u16(result,value>>16);}
std::string utf16(std::string_view text,bool terminate=false) {
  // JSON serialization validates UTF-8 before this encoder sees any caller value.
  (void)json::serialize(json::value(text));std::string out;
  for(std::size_t i=0;i<text.size();) {
    std::uint32_t point=static_cast<unsigned char>(text[i++]);unsigned following=0;
    if(point>=0xf0){point&=7;following=3;}else if(point>=0xe0){point&=15;following=2;}
    else if(point>=0xc0){point&=31;following=1;}
    while(following--){if(i>=text.size())invalid();point=(point<<6)|(static_cast<unsigned char>(text[i++])&63);}
    if(point>0xffff){point-=0x10000;u16(out,0xd800+(point>>10));u16(out,0xdc00+(point&1023));}
    else u16(out,point);
  }
  if(terminate)u16(out,0);return out;
}
std::string csv(std::string_view text) {
  std::string out="\"";for(char c:text){if(c=='"')out+='"';out+=c;}return out+'"';
}
std::string text_value(const json::value& value) {
  if(const auto* n=value.get_if<std::int64_t>())return std::to_string(*n);
  if(const auto* s=value.get_if<std::string>())return csv(*s);
  std::string out;for(const auto& v:value.as<json::array>()){if(!out.empty())out+=',';out+=csv(v.as<std::string>());}return out;
}
std::string registry_record(const json::object& d,const json::value& value) {
  const auto type=d.at("reg_type").as<std::int64_t>();std::string data;
  if(type==4||type==5||type==11) {
    const auto number=static_cast<std::uint64_t>(value.as<std::int64_t>());
    if(type==5)for(int shift=24;shift>=0;shift-=8)data.push_back(static_cast<char>(number>>shift));
    else {u32(data,static_cast<std::uint32_t>(number));if(type==11)u32(data,static_cast<std::uint32_t>(number>>32));}
  } else if(type==1||type==2)data=utf16(value.as<std::string>(),true);
  else if(type==7) {
    for(const auto& item:value.as<json::array>())data+=utf16(item.as<std::string>(),true);
    if(data.empty())u16(data,0);u16(data,0);
  } else invalid();
  std::string out=utf16("[")+utf16(d.at("path").as<std::string>(),true)+utf16(";")+
    utf16(d.at("name").as<std::string>(),true)+utf16(";");
  u32(out,static_cast<std::uint32_t>(type));out+=utf16(";");u32(out,static_cast<std::uint32_t>(data.size()));
  return out+utf16(";")+data+utf16("]");
}
}
bool override_job(const job& j){return j.number("schema")==4;}
std::string override_digest(const job& j) {
  return sha256(json::serialize(json::object{{"id",j.text("override_id")},{"revision",j.number("override_revision")},
    {"baseline_id",j.text("baseline_id")},{"backup_id",j.text("backup_id")},{"artifact_sha256",j.text("artifact_sha256")},
    {"entries",j.fields.at("override_entries")}}));
}
void validate_override_job(const job& j) {
  if(!override_job(j)||!valid_uuid(j.text("override_id"))||j.number("override_revision")<1||
      override_digest(j)!=j.text("override_sha256"))invalid();
  const auto& entries=j.fields.at("override_entries").as<json::array>();
  if(entries.empty()||entries.size()>128||json::serialize(entries).size()>8192)invalid();
  const auto& c=descriptor(j);std::string previous;
  for(const auto& item:entries) {
    const auto& entry=item.as<json::object>();if(entry.size()!=2||!entry.contains("setting_id")||!entry.contains("value"))invalid();
    const auto& id=entry.at("setting_id").as<std::string>();if(id.empty()||id<=previous)invalid();previous=id;
    const auto d=setting(c,id);validate_value(d,entry.at("value"));
    const auto* original=component(j);if(!original||std::none_of(original->files.begin(),original->files.end(),
      [&](const auto& f){return f.relative_path==d.at("file").as<std::string>();}))invalid();
  }
}
std::map<std::string,std::string> render_override_files(const job& j) {
  validate_override_job(j);const auto& c=descriptor(j);const auto* original=component(j);
  std::map<std::string,std::string> output;
  for(const auto& file:original->files) {
    const std::string name(file.relative_path);
    if(name.ends_with("/registry.pol")){output[name]="PReg";u32(output[name],1);}
    else if(name.ends_with("/GptTmpl.inf"))output[name]="";
    else if(name.ends_with("/audit.csv"))output[name]="Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n";
  }
  std::map<std::string,std::map<std::string,std::vector<std::string>>> sections;
  for(const auto& item:j.fields.at("override_entries").as<json::array>()) {
    const auto& entry=item.as<json::object>();const auto d=setting(c,entry.at("setting_id").as<std::string>());
    const auto& name=d.at("file").as<std::string>();const auto& kind=d.at("kind").as<std::string>();const auto& value=entry.at("value");
    if(!output.contains(name))invalid();
    if(name.ends_with("/registry.pol"))output[name]+=registry_record(d,value);
    else if(name.ends_with("/GptTmpl.inf")) {
      std::string line;
      if(kind=="registry")line=d.at("hive").as<std::string>()+"\\"+d.at("path").as<std::string>()+"\\"+d.at("name").as<std::string>()+
        "="+std::to_string(d.at("reg_type").as<std::int64_t>())+","+text_value(value);
      else if(kind=="system_access")line=d.at("name").as<std::string>()+"="+std::to_string(value.as<std::int64_t>());
      else if(kind=="privilege_right") {
        line=d.at("name").as<std::string>()+"=";bool first=true;
        for(const auto& v:value.as<json::array>()){if(!first)line+=',';first=false;line+="*"+v.as<std::string>();}
      } else if(kind=="service")line=csv(d.at("name").as<std::string>())+","+std::to_string(value.as<std::int64_t>())+","+csv(d.at("security_descriptor").as<std::string>());
      else invalid();
      sections[name][d.at("section").as<std::string>()].push_back(line);
    } else if(kind=="audit") {
      const auto mask=value.as<std::int64_t>();
      const auto label=mask==0?"No Auditing":mask==1?"Success":mask==2?"Failure":"Success and Failure";
      output[name]+=","+csv(d.at("target").as<std::string>())+","+csv(d.at("name").as<std::string>())+","+
        csv(d.at("path").as<std::string>())+","+label+","+csv(d.at("exclusion").as<std::string>())+","+std::to_string(mask)+"\r\n";
    } else invalid();
  }
  for(auto& [name,data]:output)if(name.ends_with("/GptTmpl.inf")) {
    std::string text="[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n";
    for(const auto& [section,lines]:sections[name]){text+="["+section+"]\r\n";for(const auto& line:lines)text+=line+"\r\n";}
    data=std::string("\xff\xfe",2)+utf16(text);
  }
  for(const auto& empty:c.empty_files) {
    if(std::none_of(original->files.begin(),original->files.end(),[&](const auto& f){return f.relative_path==empty.relative_path;}))invalid();
    if(!output.emplace(std::string(empty.relative_path),std::string(empty.content)).second)invalid();
  }
  // Only the two identity manifests may survive unchanged. Future compiled
  // payload kinds must gain a sparse renderer before an override can use them.
  for(const auto& file:original->files)if(file.relative_path!="Backup.xml"&&file.relative_path!="bkupInfo.xml"&&
      !output.contains(std::string(file.relative_path)))invalid();
  for(const auto& [name,data]:output)if(data.size()>maximum_file_bytes)invalid();
  return output;
}
}  // namespace ipms::agent::gpo
