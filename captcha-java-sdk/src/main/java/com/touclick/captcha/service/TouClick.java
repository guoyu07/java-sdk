/*
 * Copyright (C) 2008 feilong
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.touclick.captcha.service;

import static com.touclick.captcha.model.Status.STATUS_JSON_TRANS_ERROR;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.touclick.captcha.exception.TouclickException;
import com.touclick.captcha.http.HttpClient;
import com.touclick.captcha.http.Response;
import com.touclick.captcha.model.Parameter;
import com.touclick.captcha.model.Result;
import com.touclick.captcha.model.Status;
import com.touclick.captcha.util.TouclickUtil;

/**
 * The Class TouClick.
 *
 * @author zhanwei
 * @version 1.0
 * 
 *          说明：
 *          请求点触服务器进行二次验证
 * @ClassName: TouClick
 * @Description: 请求二次验证, 服务端验证
 * @date 2016年5月17日 下午4:37:06
 */
public class TouClick implements Serializable{

    /** The Constant log. */
    private static final Logger LOGGER           = LoggerFactory.getLogger(TouClick.class);

    /** The Constant serialVersionUID. */
    private static final long   serialVersionUID = -176092625883595547L;

    /** The Constant HTTP. */
    private static final String HTTP             = "http://";

    /** The Constant CHECK_POSTFIX. */
    private static final String CHECK_POSTFIX    = ".touclick.com/sverify.touclick2";

    /** The Constant CALLBACK_POSTFIX. */
    private static final String CALLBACK_POSTFIX = ".touclick.com/callback";

    //---------------------------------------------------------------

    /** The client. */
    private final HttpClient    client           = new HttpClient();

    /** <code>{@value}</code>. */
    public static final String  IP               = getIp();

    //---------------------------------------------------------------

    /**
     * 请求二次验证, 服务端验证.
     *
     * @param checkAddress
     *            二次验证地址，二级域名
     * @param sid
     *            session id
     * @param token
     *            二次验证口令，单次有效
     * @param pubKey
     *            公钥
     * @param priKey
     *            私钥
     * @return Status 返回类型
     * @throws TouclickException
     *             the touclick exception
     */
    public Status check(String checkAddress,String sid,String token,String pubKey,String priKey) throws TouclickException{
        return this.check(checkAddress, sid, token, pubKey, priKey, "", "");
    }

    /**
     * 请求二次验证, 服务端验证.
     *
     * @param checkAddress
     *            二次验证地址，二级域名
     * @param sid
     *            session id
     * @param token
     *            二次验证口令，单次有效
     * @param pubKey
     *            公钥
     * @param priKey
     *            私钥
     * @param userName
     *            请求用户名 用于统计分析
     * @param userId
     *            请求用户id 用于统计分析
     * @return Status 返回类型
     * @throws TouclickException
     *             the touclick exception
     */
    public Status check(String checkAddress,String sid,String token,String pubKey,String priKey,String userName,String userId)
                    throws TouclickException{
        Validate.notBlank(checkAddress, "checkAddress can't be blank!");
        Validate.notBlank(pubKey, "pubKey can't be blank!");
        Validate.notBlank(priKey, "priKey can't be blank!");
        Validate.notBlank(token, "token can't be blank!");
        Validate.notBlank(sid, "sid can't be blank!");

        String ran = UUID.randomUUID().toString();
        //---------------------------------------------------------------
        List<Parameter> params = new ArrayList<Parameter>();
        params.add(new Parameter("i", token));
        params.add(new Parameter("b", pubKey));
        params.add(new Parameter("s", sid));
        params.add(new Parameter("ip", IP));
        params.add(new Parameter("un", userName));
        params.add(new Parameter("ud", userId));
        params.add(new Parameter("ran", ran));

        //---------------------------------------------------------------
        String sign = TouclickUtil.buildMysign(params, priKey);

        params.add(new Parameter("sign", sign));

        StringBuilder url = new StringBuilder();
        url.append(HTTP).append(checkAddress).append(CHECK_POSTFIX);

        if (LOGGER.isDebugEnabled()){
            LOGGER.debug("url:[{}],params:[{}]", url, params);
        }

        //---------------------------------------------------------------
        Response response = client.get(url.toString(), params);

        //---------------------------------------------------------------
        LOGGER.debug("info:{}", response.getInfo());

        //---------------------------------------------------------------
        ObjectMapper mapper = new ObjectMapper();
        try{
            Result result = mapper.readValue(response.getInfo(), Result.class);
            return new Status(result.getCode(), result.getCkCode(), result.getMessage());
        }catch (Exception e){
            LOGGER.error("transfer json error ..", e);
        }
        return new Status(STATUS_JSON_TRANS_ERROR, "0", Status.getCause(STATUS_JSON_TRANS_ERROR));
    }

    /**
     * 获得 <code>{@value}</code>.
     *
     * @return the <code>{@value}</code>
     * @since 1.10.5
     */
    public static final String getIp(){
        try{
            return InetAddress.getLocalHost().getHostAddress();
        }catch (UnknownHostException e){

        }
        return null;
    }

    //---------------------------------------------------------------

    /**
     * 用户名密码校验后的回调方法.
     *
     * @param checkAddress
     *            二次验证地址，二级域名
     * @param sid
     *            session id
     * @param token
     *            二次验证口令，单次有效
     * @param pubKey
     *            the pub key
     * @param priKey
     *            the pri key
     * @param isLoginSucc
     *            用户名和密码是否校验成功
     * @throws TouclickException
     *             the touclick exception
     */
    public void callback(String checkAddress,String sid,String token,String pubKey,String priKey,boolean isLoginSucc)
                    throws TouclickException{
        if (checkAddress == null || "".equals(checkAddress) || token == null || "".equals(token) || pubKey == null || "".equals(pubKey)
                        || priKey == null || "".equals(priKey) || sid == null || "".equals(sid)){
            throw new TouclickException("参数有误");
        }

        List<Parameter> params = new ArrayList<Parameter>();
        params.add(new Parameter("i", token));
        params.add(new Parameter("b", pubKey));
        params.add(new Parameter("s", sid));
        params.add(new Parameter("ip", IP));
        params.add(new Parameter("su", isLoginSucc ? "1" : "0"));
        String ran = UUID.randomUUID().toString();
        params.add(new Parameter("ran", ran));

        String sign = TouclickUtil.buildMysign(params, priKey);
        params.add(new Parameter("sign", sign));

        StringBuilder url = new StringBuilder();
        url.append(HTTP).append(checkAddress).append(CALLBACK_POSTFIX);

        try{
            client.get(url.toString(), params);
        }catch (TouclickException e1){
            LOGGER.error(e1.getMessage());
        }
    }

    //---------------------------------------------------------------

    /**
     * Builds the sign.
     *
     * @param code
     *            the code
     * @param ran
     *            the ran
     * @param priKey
     *            the pri key
     * @return the string
     */
    private String buildSign(int code,String ran,String priKey){
        List<Parameter> params = new ArrayList<Parameter>();
        params.add(new Parameter("code", code));
        params.add(new Parameter("timestamp", ran));
        return TouclickUtil.buildMysign(params, priKey);
    }

}
