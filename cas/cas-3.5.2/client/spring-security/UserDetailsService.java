package cn.com.wavenet.security.service;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import com.github.abel533.sql.SqlMapper;

import cn.com.wavenet.core.bean.SelectSqlBean;
import cn.com.wavenet.core.bean.WavenetUser;
import cn.com.wavenet.core.service.DataManager;
import cn.com.wavenet.hydro.util.StringUtils;

/**
 * 
 * @ClassName: UserDetailsService
 * @Description: TODO(用户业务实现类 实现AuthenticationUserDetailsService 单点登陆实现类)
 * @author shil
 * @date 2017年9月18日 下午1:42:56
 *
 */
@Repository("cn.com.wavenet.security.service.UserDetailsService")
public class UserDetailsService implements AuthenticationUserDetailsService {

	private static final Logger logger = Logger.getLogger(UserDetailsService.class);

	@Resource
	SqlMapper sqlMapper;

	@Override
	public UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException {
		List<GrantedAuthority> auths = new ArrayList<GrantedAuthority>();
		CasAssertionAuthenticationToken casauth = null;
		if (token instanceof CasAssertionAuthenticationToken) {
			casauth = (CasAssertionAuthenticationToken) token;
			casauth.getAssertion().getPrincipal().getName();
			Map<String, Object> attr = casauth.getAssertion().getPrincipal().getAttributes();
			String username = casauth.getAssertion().getPrincipal().getName();
			if (username == null || username == "" || username.equals("")) {
				String message = "用户：[" + username + "]不存在";
				logger.error(message);
				throw new UsernameNotFoundException(message);
			}

			Map userMap = new HashMap();
			try {
				 userMap=sqlMapper.selectOne("select t.*,t.st_sid ST_LOGINNAME from T_HY_EMP_I t where st_sid=#{ST_LOGINNAME}",username);
			} catch (NullPointerException | IndexOutOfBoundsException  e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			// 获取用户信息
			Collection<GrantedAuthority> grantedAuths = null;
			try {
				grantedAuths = obtionGrantedAuthorities(username);
			} catch (NullPointerException | SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			List<Map<String, Object>> resourceList = getUserSource(username);
			boolean enables = true;
			boolean accountNonExpired = true;
			boolean credentialsNonExpired = true;
			boolean accountNonLocked = true;
			WavenetUser userdetail = new WavenetUser(userMap.get("ST_LOGINNAME").toString(),
					userMap.get("ST_PASS").toString(), enables, accountNonExpired, credentialsNonExpired,
					accountNonLocked, grantedAuths);
			
			//更新登录时间
			sqlMapper.update("update T_HY_EMP_I set DT_LASTLOGIN=sysdate where st_sid=#{userid}",username);
			//获取用户其他信息
			try {
				userMap.putAll(sqlMapper.selectOne("select connstr(decode(st_name,'职务',F_GET_PARAMStr(st_content),'')) as jobname,\r\n" + 
						"connstr(decode(st_name,'部门',F_GET_ORGNAME(st_content),'')) as deptname,\r\n" + 
						"connstr(decode(st_name,'部门',st_content,'')) deptid,\r\n" + 
						"connstr(decode(st_name,'头像名称',st_content,'')) loginimg from t_hy_emp_is i where st_pid=#{userid}",username));
				userMap.putAll(sqlMapper.selectOne("select connstr(decode(st_name,'地址',F_GET_PARAMStr(st_content),'')) as deptaddress \r\n" + 
						"from t_hy_org_is where st_pid=#{deptid}",userMap.get("DEPTID")));
			} catch (Exception e) {
				String message = "用户：["+username +"]资料不全";
				logger.error(message);
				//throw new UnableToSendNotificationException(message);
			}
			SimpleDateFormat myFmt=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");  
	        String time = myFmt.format( userMap.get("DT_LASTLOGIN"));  
		    //userMap.get("DT_LASTLOGIN")
	        userMap.put("DT_LASTLOGIN", time);
			userdetail.setUserMap(userMap);
			
			
			return userdetail;

		}
		return null;
	}

	/**
	 * 根据用户名获取用户权限 Set<GrantedAuthority>
	 * 
	 * @param username
	 * @return
	 * @throws NullPointerException
	 * @throws SQLException
	 */
	private Set<GrantedAuthority> obtionGrantedAuthorities(String username) throws NullPointerException, SQLException{
		Set<GrantedAuthority> authSet = new HashSet<GrantedAuthority>();
		List<Map<String, Object>> list = getUserSource(username);
		if(list == null){
			return null ;
		}
		for (int i = 0; i < list.size(); i++) {
			if (logger.isDebugEnabled()) {
				logger.debug("用户：[" + username + "]拥有资源：["
						+ StringUtils.toStr(list.get(i).get("ST_APATH")) + "],即spring security中的access");
			}
			try {
				if(null==list.get(i) || null==list.get(i).get("ST_APATH")){
					continue;
				}
				authSet.add(new SimpleGrantedAuthority(StringUtils.toStr(list.get(i).get("ST_APATH"))));
			} catch (Exception e) {
				e.printStackTrace();
				System.out.println("="+e.getMessage());
			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("loadUserByUsername(String) - end"); 
		}
		return authSet;
	}

	/**
	 * 
	 * @Title: getUserSource @Description: TODO(根据用户名获取用户资源) @author shil @date
	 * 2017年9月18日 下午1:26:58 @param @param username @param @return 设定文件 @return
	 * List<Map<String,Object>> 返回类型 @throws
	 */
	private List<Map<String, Object>> getUserSource(String username){
		String sql = "select * from T_HY_RESOURCE r where EXISTS(\r\n" + 
				"select * from T_HY_ROLEMODULE_N n where EXISTS (\r\n" + 
				"select nm_sid from t_hy_role_i where nm_sid in(select st_content from t_hy_emp_is where st_name like '%角色' and st_pid='"+username+"' UNION ALL \r\n" + 
				"select st_content from t_hy_org_is where st_name like '%角色') and n.nm_rolesid=nm_sid\r\n" + 
				") and r.nm_sid=n.nm_modulesid\r\n" + 
				") and r.NM_STATE=1";
		List<Map<String, Object>> list = null;
		try {
			list = sqlMapper.selectList(sql);
		} catch (NullPointerException e) {
			logger.debug("获取用户权限空之争"); 
			e.printStackTrace();
		}
		return list;
	}

}
