package com.lsitc.global.util;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lsitc.global.error.exception.BusinessException;
import com.lsitc.global.error.exception.ErrorCode;

public class JsonUtils {
    /**
     * @methodName  : objectToJson
     * @date        : 2021.02.24
     * @desc        : object를 json으로 바꿔 반환한다.
     * @param cvtObject
     * @return
     */
    
    public static String objectToJson(Object cvtObject){
        String cvtJson = null;
        if( cvtObject == null ) {
            return null;
        }
        
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(Include.NON_NULL);
        try {
            // Convert object to JSON string
            cvtJson = mapper.writeValueAsString(cvtObject);
        } catch (Exception e) {
            //FIXME 다국어 처리
            throw new BusinessException("변환중 에러가 발생하였습니다.", ErrorCode.INTERNAL_SERVER_ERROR);
        }
        
        return cvtJson;
    }

    /**
     * 
     * @methodName  : objectToJson
     * @date        : 2021.02.24
     * @desc        : object를 json로 바꿔 반환한다.
     *                Include Option을 지정할 수 있다.
     * @param cvtObject
     * @param include
     * @return
     */
    public static String objectToJson(Object cvtObject, Include include) {
        String cvtJson = null;

        if (cvtObject == null) {
            return null;
        }

        ObjectMapper mapper = new ObjectMapper();

        mapper.setSerializationInclusion(include);
        try {
            // Convert object to JSON string
            cvtJson = mapper.writeValueAsString(cvtObject);
        } catch (Exception e) {
            //FIXME 다국어 처리
            throw new BusinessException("변환중 에러가 발생하였습니다.", ErrorCode.INTERNAL_SERVER_ERROR);
        }
        return cvtJson;
    }

    /**
     * @methodName  : jsonToObject
     * @date        : 2021.02.24
     * @desc        : json을 Object로 바꿔 반환한다.
     * @param <T>
     * @param boundClass
     * @param json
     * @param ignoreUnknownProperties
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static <T> T jsonToObject(Class<T> boundClass, String json, boolean ignoreUnknownProperties) throws Exception{
        ObjectMapper mapper = new ObjectMapper();
        Object bean = null;
        try {
            if (ignoreUnknownProperties) {
                mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            }
            bean = mapper.readValue(json, boundClass);
            
        } catch (Exception e) {
            //FIXME 다국어 처리
            throw new BusinessException("변환중 에러가 발생하였습니다.", ErrorCode.INTERNAL_SERVER_ERROR);
        }

        return (T) bean;
    }

    /**
     * @methodName  : jsonToObject
     * @date        : 2021.02.24
     * @desc        : json을 객체로 변환한다.
     * @param <T>
     * @param boundClass
     * @param json
     * @return
     * @throws Exception
     */
    public static <T> T jsonToObject(Class<T> boundClass, String json) throws Exception{
        return jsonToObject(boundClass, json, false);
    }
    
    /**
     * 
     * @methodName  : jsonToObject
     * @date        : 2021.02.24
     * @desc        : josn을 객체로 변환한다.
     * @param <T>
     * @param boundClass
     * @param json
     * @param failOnUnknownProperties
     * @param failOnUnresolvedObjectIds
     * @return
     * @throws Exception
     */
    public static <T> T jsonToObject(Class<T> boundClass, String json, boolean failOnUnknownProperties, boolean failOnUnresolvedObjectIds) throws Exception {
        return jsonToObject(boundClass, json, failOnUnknownProperties, failOnUnresolvedObjectIds, true);
    }

    /**
     * @methodName  : jsonToObject
     * @date        : 2021.02.24
     * @desc        : json을 객체로 반환한다.
     * @param <T>
     * @param boundClass
     * @param json
     * @param failOnUnknownProperties
     * @param failOnUnresolvedObjectIds
     * @param acceptSingleValueAsArray
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static <T> T jsonToObject(Class<T> boundClass, String json, boolean failOnUnknownProperties, boolean failOnUnresolvedObjectIds, boolean acceptSingleValueAsArray) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Object bean = null;
        try {
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, failOnUnknownProperties);
            mapper.configure(DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS, failOnUnresolvedObjectIds);
            mapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, acceptSingleValueAsArray);
            bean = mapper.readValue(json, boundClass);
        } catch (Exception e) {
            //FIXME 다국어 처리
            throw new BusinessException("변환중 에러가 발생하였습니다.", ErrorCode.INTERNAL_SERVER_ERROR);
        }
        return (T) bean;
    }
}
