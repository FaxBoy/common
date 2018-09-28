package cn.com.wavenet.shslc.login;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import cn.com.wavenet.frame.core.dao.DataManager;
import cn.com.wavenet.frame.core.dao.DataObject;
import cn.com.wavenet.frame.core.dao.DataObjectUtil;
import cn.com.wavenet.frame.core.util.DateFormat;
import cn.com.wavenet.hydro.login.LoginForm;
import cn.com.wavenet.hydro.login.WaveUserInfo;
import cn.com.wavenet.hydro.util.CookieUtil;
import cn.com.wavenet.hydro.util.DBUtil;
import cn.com.wavenet.hydro.util.GlobalParam;
import cn.com.wavenet.hydro.util.JSONUtil;
import cn.com.wavenet.hydro.util.LoginFunc;
import cn.com.wavenet.hydro.util.SecurityUtil;
import cn.com.wavenet.shdike.util.GlobalFunc;

public class CasLoginAction extends Action {
	public ActionForward execute(ActionMapping actionMapping, ActionForm actionForm,
            HttpServletRequest request, HttpServletResponse response) throws Exception {
		//数据库连接
	
		WaveUserInfo wui = new WaveUserInfo();
		LoginForm loginForm = (LoginForm) actionForm;
		//String tablespace=GlobalParam.getDbSchameName();
		String forwardType=loginForm.getSupertype();
		forwardType=GlobalFunc.formatNull(forwardType, "successV6");
		
		HttpSession session = request.getSession(true);
		JSONObject jsonClientInfo=getClinetInfo(loginForm,request);
		DataObject dbo_info = new DataObject();
		Boolean userCheckFlag=false;
		Connection conn=null;
		String userId = (String)session.getAttribute("USERIDNAME");
		loginForm.setEmpid(userId);
		JSONObject jsonUser=getUserCheck(loginForm,request);
		try {			
			
			
			//判断验证码是否正确
			userCheckFlag=this.checkYz(jsonUser,request);
			if(!userCheckFlag){
				//loginForm.setYzFlag("false");
				return (actionMapping.findForward("failure"));
			}
			//检查用户是否被锁定
			 conn= DataManager.getConnection();
			DataManager dataManger = DataManager.getInstance(conn);
			userCheckFlag=this.checkLocked(dataManger, jsonUser);
			if(!userCheckFlag){
				loginForm.setLockFlag("false");
				return (actionMapping.findForward("failure"));
			}
			dbo_info=getUserInfo(dataManger,jsonUser);
			//检查用户登录是否成功
			userCheckFlag=this.checkUserLogin(dataManger,jsonUser,dbo_info);
			if(!userCheckFlag){//失败
				//检查登录失败的次数
				String results=this.checkFailcount(dataManger, jsonUser);
				if(results.equals("loginFlag")){
					loginForm.setLoginFlag("false");
				}else if(results.equals("lockFlag")){
					loginForm.setLockFlag("false");
				}else{
					loginForm.setLoginFlag("false");
				}
				return (actionMapping.findForward("failure"));
			}else{//成功
				//获取用户信息
				
				//保存用户信息
				String userID=dbo_info.getString("userid");
				dbo_info=GlobalFunc.mergetDbo(dbo_info, this.getDeskInfo(userID, dataManger));//将首页的信息合并到session中
				wui=setUserInfo(dbo_info);
				String orgSid=dbo_info.getString("DEPTID");
				//this.setFirstPage(dataManger, wui);//首页默认显示
				loginForm.setLoginFlag(userCheckFlag.toString());

				String sysRole=dbo_info.getString("all_系统角色");
				
				wui.setRoleLevel(getRoleMap(dataManger,sysRole));//获取用户的角色（部门，用 户）编号
				String webRole=GlobalFunc.formatNull(dbo_info.getString("all_一般角色"),"");
				
				try{
				if(GlobalFunc.isNull(webRole)&&GlobalFunc.formatIsNotNull(sysRole)){
					webRole=dbo_info.getString("all_系统角色");
				}else if(GlobalFunc.formatIsNotNull(webRole)&&GlobalFunc.formatIsNotNull(sysRole)){
					webRole+=","+dbo_info.getString("all_系统角色");
				}
				if(webRole.lastIndexOf(",")==webRole.length()-1){
					webRole.substring(0, webRole.length()-1);
				}}catch(Exception ee){}
				List<DataObject> listAll=this.getPermission(dataManger, webRole);						
				JSONArray jsonArray = getTreeJsonData(listAll,wui);
				
				loginForm.setRoles(jsonArray.toString());
				this.setSession(dbo_info, wui, jsonArray, session);//保存至session				
				//保存日志信息
				LoginFunc.saveAPPLogin(dataManger,dbo_info,jsonUser,jsonClientInfo);
				//设置cookie
				this.setCookie(jsonUser, response);
				return (actionMapping.findForward(forwardType));					
				}				
		}catch(Exception e){
			e.printStackTrace();
			return (actionMapping.findForward("failure"));
			//return actionMapping.findForward(Constant.GLOBAL_ERROR_FORWARD);
		}finally{
			if(conn!=null) {
				DBUtil.destoryDBObj(conn);
			}
				
		}
	  }
	/**
	 * 获得用户的首页桌面信息
	 * @param userID
	 * @param dm
	 * @return
	 */
	protected DataObject getDeskInfo(String userID,DataManager dm){
		DataObject dbo=new DataObject();
		dbo.setInt("desk_rows",4);//首页显示行数 
		dbo.setInt("desk_height", 4*400);//首页的高度
		//dbo.setString("desk_sid_row1", "1");
		dbo.setString("desk_name_row_1", "日常办公");
		dbo.setString("desk_name_row_2", "防汛安全");
		dbo.setString("desk_name_row_3", "巡查管理");
		dbo.setString("desk_name_row_4", "泵闸运行");
		//dbo.setString("desk_url_row1", "日常办公");
		return dbo;
	}
	//设置cookie
	protected void setCookie(JSONObject jsonUser, HttpServletResponse response){
		String userId=JSONUtil.getJsonProp(jsonUser, "userID");
		String passWord=JSONUtil.getJsonProp(jsonUser, "userPass");
		
		CookieUtil.setCookie(response, "autoLoginUser", userId);
		CookieUtil.setCookie(response, "autoLoginPass", passWord);
	}
	
	
	
	protected JSONArray getTreeJsonData(List<DataObject> bean,WaveUserInfo wui){
		//List<TreeMap<String,Object>> list = new LinkedList<TreeMap<String,Object>>();
		JSONArray list = new JSONArray();
		for(DataObject dto:bean){
			//根节点			
			JSONObject root = new JSONObject();
			root.put("lev", dto.getString("LEV"));
			root.put("nm_sid", dto.getString("NM_SID"));
			root.put("st_name", dto.getString("ST_NAME"));
			root.put("nm_pid", dto.getString("NM_PID"));
			String url = dto.getString("ST_URL");
			url = getRealUrl(url,"(\\$\\w+)",wui);
			root.put("st_url", url);
			root.put("st_img", dto.getString("ST_IMG"));
			root.put("st_urlparam", dto.getString("ST_URLPARAM"));
			JSONArray charid = getTreeJsonData(dto.getTree(),wui);
			if(charid.size()>0){
				//root.put("children", charid);
				root.put("children", charid);
			}
			list.add(root);
		}
		return list;
	}
	/**
	 * 检查用户是否被锁定
	 * @param dm
	 * @param actionForm
	 * @param userId
	 * @return
	 */
	protected  boolean checkLocked(DataManager dm,JSONObject jsonUser){
		DataObject obj=null;
		//if(GlobalParam.getJSON_MAPBoolean("SYSTEM","system.img.init")){
		try {					
			String CurrTime = DateFormat.getCurrent();
			String userId=jsonUser.getString("userID");
			String sql="select * from t_hy_login_is where st_loginname=?";
			obj=dm.findByPrimaryKey(sql,userId);
			if(DataObjectUtil.isNull(obj)){
				return true;
			}else{
				
				String count=obj.getString("nm_failcount");
				String lastLoginDate=obj.getString("dt_lastlogindate");
				int failcount=0;
				if(count==""||count==null){
					failcount=0;
				}else{
					failcount=Integer.parseInt(count);
				}
				//比较时间
				int result=GlobalFunc.compareTime(CurrTime,lastLoginDate); 
				//当前时间小于锁定时间
				if(result==-1&&failcount==-1){
					return false;
				}else if(failcount==-1){
					sql="update T_HY_LOGIN_IS t set NM_FAILCOUNT=0 where ST_LOGINNAME='"+userId+"'";
					dm.update(sql,null);	
					return true;
				}
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return true;
	}
	
	/**
	 * 判断验证码输入是否正确
	 * @param sysTxt 系统生成的验证码
	 * @param inputTxt  用户输入的验证码
	 * @return
	 */
	protected  boolean checkYz(JSONObject jsonUser,HttpServletRequest request){
		//当启用验证码验证的时候
		if(GlobalParam.getJSON_MAPBoolean("SYSTEM","system.img.init")){
			String inputTxt=jsonUser.getString("userCheck");//页面输入的验证码
			HttpSession session = request.getSession(true);
			String sysTxt=(String) session.getAttribute("rand");//系统生成的验证码
			if(!inputTxt.equals(sysTxt)){
				return false;
			}else{
				return true;
			}
		}
		return true;
	}
	
	/**
	 * 验证用户信息
	 * @return
	 */
	protected  boolean checkUserLogin(DataManager dm,JSONObject jsonUser,DataObject dboUser){
		try {		
			String userId=jsonUser.getString("userID");
			/*String sql="select *  from "+GlobalParam.getJSON_MAP("DB_VIEWTABLE", "view.user")+" where userid=?";
			DataObject result=dm.findByPrimaryKey(sql, userId);*/
			if(GlobalParam.DEBUGFLAG){
				return true;
			}else{
				String passWord=jsonUser.getString("userPass");
				String shujukuPass=dboUser.getString("st_pass");
				
				//用md5对输入的密码和数据库中的密码进行加密,
				String shuru=SecurityUtil.md5Encrypt(passWord);
				String shujukuPassword=SecurityUtil.md5Encrypt(shujukuPass);//对数据库中存储的用户密码进行加密		
				//如果输入的密码和数据库里边的不一致
				if(!shuru.equals(shujukuPassword)){
					//登录失败
					return false;
				}else{
					//登录成功
					return true;
				}	
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * 检查用户登录失败的次数
	 * @param dm
	 * @param userId 用户登陆名
	 * @param count 
	 * @return
	 */
	protected String checkFailcount(DataManager dm,JSONObject jsonUser){
		String userId=jsonUser.getString("userID");
		String CurrTime = DateFormat.getCurrent();
		DataObject dbo=new DataObject("T_HY_LOGIN_IS");
		DataObject obj=null;
		dbo.setString("st_loginname", userId);
		//dbo.setString("st_token", "");
		int failcounts;
		try {
			String sql="select * from t_hy_login_is where st_loginname=?";
			obj=dm.findByPrimaryKey(sql,userId);
			boolean flags=DataObjectUtil.isNull(obj);
			if(flags==false){
				String counts=obj.getString("nm_failcount");
				failcounts=Integer.parseInt(counts);
				int global_count=GlobalParam.getJSON_MAPInt("SYSTEM", "system.login.count")-1;
				if(failcounts<global_count){
					failcounts++;
					dbo.setInt("nm_failcount", failcounts);
					dbo.setString("dt_lastlogindate", CurrTime);
					dm.update(dbo);
					return "loginFlag";
				}else if(failcounts==global_count){
					//当前时间加上半个小时后的时间
					String lockTime=GlobalFunc.getNearDate(30, "yyyy-MM-dd HH:mm:ss");
					dbo.setInt("nm_failcount", -1);
					dbo.setString("dt_lastlogindate", lockTime);
					dm.update(dbo);
					return "lockFlag";
				}
			}else if(flags==true){
				dbo.setInt("nm_failcount", 1);
				dbo.setString("dt_lastlogindate", CurrTime);
				dm.insert(dbo);
				return "loginFlag";
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "loginFlag";
		
		
	}

	
	/**
	 * 获得用户信息
	 * @return
	 */
	protected  DataObject getUserInfo(DataManager dm ,JSONObject jsonUser){
		DataObject dbo=new DataObject();
		DataObject info = null;	
		Collection<DataObject> col = null;
		String userid=jsonUser.getString("userID");
		try {
			//TODO 查询用户信息
			String sql="select  *  from "+GlobalParam.getJSON_MAP("DB_VIEWTABLE", "view.user")+"   where userid=?";
			info=dm.findByPrimaryKey(sql, userid);
			info.setString("st_loginname", info.getString("userid"));
			String tsql="select  pack_sys.f_get_param_name(st_content) st_content from t_hy_com_is "+
					"where st_comsid=? and st_name='是否是第三方单位'";
			dbo=dm.findByPrimaryKey(tsql,info.getString("compid"));
			boolean isthree=false;
			if(dbo!=null){
				String three=dbo.getString("content");
				if("是".equals(three)){
					isthree=true;
				}else{
					isthree=false;
				}
			}
			info.setBoolean("isThree", isthree);
			//System.out.println(info.getString("deptid"));
			String orgSid=info.getString("deptid");
			//详细信息
			DataObject dboExtend=doGetUserInfoDetail(dm,userid,orgSid);
			//合并两条DataObject数据
			info=GlobalFunc.mergetDbo(info, dboExtend);
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return info;
	}
	/**
	 * 获得用户详细信息
	 * @param dm
	 * @param userid
	 * @param orgSid
	 * @return
	 */
	
	protected DataObject doGetUserInfoDetail(DataManager dm,String userId,String orgSid){
		// TODO Auto-generated method stub
		DataObject dboUserInfo=new DataObject();
		

		dboUserInfo.setString("defaultIndex", "0");
		DataObject info = null;		
		String sName;
		String sContent;
		Collection<DataObject> col = null;
		
			String empSql = "select st_name,wmsys.wm_concat(st_content) st_content from t_hy_emp_is t" +
					" where st_pid =? group by st_name";
			try{
				col = dm.find(empSql, userId);
				Iterator<DataObject> i = col.iterator();
				
				while(i.hasNext()){
					info = i.next();
					sName = info.getString("ST_NAME");
					sContent = info.getString("ST_CONTENT");
					dboUserInfo.setString("emp_"+sName, sContent);
				}	
			}catch(Exception e){
				
			}
			String tmpOrgSid="'"+orgSid.replaceAll(",", "','")+"'";
			dboUserInfo.setString("orgsids", tmpOrgSid);
			String deptSql = "select st_name,wmsys.wm_concat(st_content) st_content from T_HY_ORG_IS t" +
					" where st_orgsid in ("+tmpOrgSid+")" +
					" group by st_name";
			try{
				col = dm.find(deptSql, null);
				Iterator<DataObject> i = col.iterator();				
				while(i.hasNext()){
					info = i.next();
					sName = info.getString("ST_NAME");
					sContent = info.getString("ST_CONTENT");
					dboUserInfo.setString("org_"+sName, sContent);
					
				}
				String[] allInfo={"系统角色","一般角色"};
			for(String s:allInfo){
				String tmp=dboUserInfo.getString("emp_"+s);
				if(!GlobalFunc.isNull(tmp)){
					if(!GlobalFunc.isNull(dboUserInfo.getString("org_"+s)))
					tmp+=","+dboUserInfo.getString("org_s");
				}else{
					tmp=dboUserInfo.getString("org_系统角色");
				}
				dboUserInfo.setString("all_"+s, tmp);
			}
			}catch(Exception e){
				e.printStackTrace();
			}
		
		return dboUserInfo;
	}
	
	/**
	 * 获取用户权限
	 * @param dm
	 * @param roleMap 用户的角色列表
	 * @param tablespace
	 * @return
	 */
	protected  List<DataObject> getPermission(DataManager dm,String roleMap){
		try {

			StringBuffer sb=new StringBuffer();
			//roleMap="51587";

			if(GlobalFunc.isNull(roleMap)){
				roleMap="51587";//这应该是默认角色
			}
			sb.append( " with t_module as (select  nm_modulesid  from t_hy_rolemodule_n c  ")
				.append( " where c.nm_rolesid in ("+roleMap+")) ")
				.append( " ,t_menu as (select a.nm_sid,trim(a.st_name) st_name,a.nm_pid,a.st_img,a.nm_ord,trim(b.st_url) st_url,b.st_urlparam,a.nm_modulesid  ") 
				.append( " from "+GlobalParam.getJSON_MAP("DB_VIEWTABLE", "table.menu")+" a,t_hy_module_i b   where a.nm_modulesid=b.nm_sid)")
				.append( " ,tresult as ( select distinct e.* from t_menu e,t_module d where e.nm_modulesid=d.nm_modulesid )") 
				.append( "select  LEVEL as lev,e.nm_modulesid,e.nm_sid,e.st_name,e.nm_pid,e.st_img,e.st_url,e.st_urlparam  ,e.nm_ord ")
				.append(" from tresult e START WITH e.nm_pid=0 CONNECT BY PRIOR e.nm_sid=e.nm_pid order siblings by e.nm_ord asc");
			
			
			Collection<DataObject> roleList = dm.find(sb.toString(), null);
			
			List list =(List)roleList;
			List<DataObject> listAll = new ArrayList<DataObject>();
			Map<String, DataObject> map = new LinkedHashMap<String, DataObject>();
			for (int i2 = 0; i2 < list.size(); i2++) {
				DataObject dto = (DataObject) list.get(i2);
				int id = dto.getInt("NM_SID");
				//System.out.println("id==="+id);
				// 用id作为hash表的key,value为this.
				map.put(id + "", dto);
			}
			// 迭代取出hash表的key
			Iterator<String> it = map.keySet().iterator();
			while (it.hasNext()) {
				// 取出key
				String sid = (String) it.next();	
				// 取出key所对应的value对象。并取出父ID的值。
				DataObject dto = (DataObject) map.get(sid);
				int pid = dto.getInt("NM_PID");
				if (pid == 0) {
					listAll.add(dto);
				} else {
					// 取出父节点对象
					DataObject pdto = (DataObject) map.get(pid + "");
					// 将子节点添加到父节点上
					pdto.getTree().add(dto);;
				}
			}

			return listAll;
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return null;
	}
	
	/**
	 * 返回用户的系统管理角色等级
	 */
	protected  String getRoleMap(DataManager dm,String sysRole){
			String roleSLevel="0";
		
			if(!GlobalFunc.isNull(sysRole)){
				
				String rolesql="select max(nm_role_level) rolelevel from t_hy_role_i t where nm_sid in ("+sysRole+")";
				try{
				DataObject roledata=dm.findByPrimaryKey(rolesql,null);
				roleSLevel=roledata.getString("rolelevel");
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
			}
		return roleSLevel;		
	}
	
	
	
	/**
	 * //根据部门类型判断首页默认显示
	 * @param dataManger
	 * @param wui
	 */
	/*protected  void setFirstPage(DataManager dataManger,WaveUserInfo wui){
		try {
			String findDeptTypeSql="select nm_sid,st_name,st_content from T_HY_PARAM_I where nm_lid=1041 and st_name in(";
			findDeptTypeSql+="select s.st_content from T_HY_ORG_IS s where s.st_name='部门类型' and s.st_orgsid in(?) )";
			DataObject deptTypeDbo = dataManger.findByPrimaryKey(findDeptTypeSql, new String[]{wui.getDepartmentId()});
			String defaultIndex="0";
			if(deptTypeDbo!=null){
				defaultIndex=deptTypeDbo.getString("st_content");
			}
			String []userdept=wui.getDepartmentId().split(",");
			String userde="";
			for(String dept:userdept){
				userde+="'"+dept+"',";
			}
			userde=userde.substring(0,userde.length()-1);
			findDeptTypeSql="select s.st_orgsid||'_'||s.st_content st_content from T_HY_ORG_IS s where s.st_name='上级直管' and s.st_orgsid in(" 
				+userde+	")";
			
			deptTypeDbo=dataManger.findByPrimaryKey(findDeptTypeSql, null);
			String suborg=null;
			if(deptTypeDbo!=null){
				suborg=deptTypeDbo.getString("st_content");
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}*/
	
	public void setSession(DataObject dbo,WaveUserInfo wui,JSONArray jsonArray,HttpSession hs){
		if(dbo!=null){
			dbo.setString("roleMaps", jsonArray.toString());
			wui.setDboInfo(dbo);
			hs.setAttribute("userView", wui);
			
			//hs.setAttribute("userInfo", dbo);
			
		}
		hs.setMaxInactiveInterval(60*60);
		hs.setAttribute("cn.com.wavenet.menus", jsonArray);
	}
	
	protected WaveUserInfo getUserSession(HttpSession hs){
		Object obj=hs.getAttribute("userView");
		
		if(obj!=null){
			try{
			WaveUserInfo wui=(WaveUserInfo)obj;
				return wui;
			}catch(Exception e){
				return null;
			}
		}
		return null;
	}
	/**
	 * 设置用户信息
	 * @param obj
	 * @return
	 */
	public WaveUserInfo setUserInfo(DataObject obj){
		WaveUserInfo wui = new WaveUserInfo();
		wui.setUserName(obj.getString("userid")); //用户id
		wui.setUserCNName(obj.getString("username"));//用户中文名称
		wui.setUserId(obj.getString("userid"));
		wui.setDepartmentName(obj.getString("deptname"));//部门名称				
		wui.setDepartmentId(obj.getString("deptid"));//部门id
		wui.setCorpId(obj.getString("compid"));//所在单位
		wui.setCorpName(obj.getString("compname"));
		wui.setMp(obj.getString("emp_手机"));
		wui.setMail(obj.getString("emp_邮箱"));
		//所属区县
		String userArea=obj.getString("org_所属区县");
		
		if(!GlobalFunc.isNull(userArea)){
			wui.setAreaId(userArea);
		}
		wui.setDboInfo(obj);
		return wui;
	}
	protected JSONObject getUserCheck(LoginForm loginForm,HttpServletRequest request){
		
		JSONObject jsonCheck=GlobalParam.getJsonMap("USERCHECK_INFO");

		try {
			jsonCheck.put("userID", loginForm.getEmpid().trim());
			jsonCheck.put("userPass", loginForm.getEmppwd());
			jsonCheck.put("userTkn", "");
			jsonCheck.put("userCheck", loginForm.getYz());
		} catch (Exception e) {
			return null;
		}
		return jsonCheck;
		
	}
	/**
	 * 获得浏览器信息
	 * @param loginForm
	 * @param request
	 * @return
	 */
	protected JSONObject getClinetInfo(LoginForm loginForm,HttpServletRequest request){
		String reqBrowser = request.getHeader("User-Agent");
		JSONObject jsonCheck=GlobalParam.getJsonMap("CLIENT_INFO");
		jsonCheck.put("IP","");
		jsonCheck.put("IEVERSION",reqBrowser);
		jsonCheck.put("accountType","pc");
		return jsonCheck;
		
	}
	protected String getRealUrl(String str,String rule,WaveUserInfo wui){
		Pattern p = Pattern.compile(rule);
		Matcher m = p.matcher(str);
		m.regionEnd();
		//Boolean b = m.find();
		StringBuffer sb = new StringBuffer();
		while(m.find()){
			String paramName = m.group();
			String uParamName = paramName.substring(1);
			String value = "";
			try {
				Method method = wui.getClass().getMethod("get"+uParamName);
				value = (String) method.invoke(wui);
				value = GlobalFunc.isNull(value)?"":value;
			} catch (SecurityException e) {
				e.printStackTrace();
			} catch (NoSuchMethodException e) {
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				e.printStackTrace();
			}
			m.appendReplacement(sb,value);
			//m.appendTail(sb);
		}
		String url = sb.toString();
		/*if(url.indexOf("?&")!=-1){
			url.replaceFirst("\\$", "");
		}*/
		return GlobalFunc.isNull(url)?str:url;
	}
}



	



	

