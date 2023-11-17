package com.lsitc.global.mybatis;

import com.lsitc.global.auditing.Auditable;
import com.lsitc.global.auditing.AuditingHandler;
import com.lsitc.global.auditing.SoftDeletable;
import com.lsitc.global.auditing.SoftDeletingHandler;
import java.util.Collection;
import lombok.RequiredArgsConstructor;
import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.session.defaults.DefaultSqlSession.StrictMap;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
@Intercepts({
    @Signature(type = Executor.class, method = "query",
        args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class,
            CacheKey.class, BoundSql.class}),
    @Signature(type = Executor.class, method = "query",
        args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}),
    @Signature(type = Executor.class, method = "update",
        args = {MappedStatement.class, Object.class})
})
public class MybatisInterceptor implements Interceptor {

  private final AuditingHandler auditingHandler;
  private final SoftDeletingHandler softDeletingHandler;

  @SuppressWarnings("unchecked")
  @Override
  public Object intercept(Invocation invocation) throws Throwable {
    markAudited(invocation);

    return invocation.proceed();
  }

  private void markAudited(Invocation invocation) {
    Object parameter = invocation.getArgs()[1];
    String executorMethodName = invocation.getMethod().getName();
    SqlCommandType sqlCommandType = ((MappedStatement) invocation.getArgs()[0]).getSqlCommandType();

    if (isCollection(parameter)) {
      markCollection((StrictMap) parameter, executorMethodName, sqlCommandType);
    } else {
      markSingleObject(parameter, executorMethodName, sqlCommandType);
    }
  }

  private boolean isCollection(Object parameter) {
    return parameter instanceof StrictMap;
  }

  private void markCollection(StrictMap parameter, String executorMethodName,
      SqlCommandType sqlCommandType) {
    if (parameter.containsKey("collection")) {
      for (Object collectionParam : (Collection) parameter.get("collection")) {
        markSingleObject(collectionParam, executorMethodName, sqlCommandType);
      }
    } else if (parameter.containsKey("array")) {
      for (Object collectionParam : (Object[]) parameter.get("array")) {
        markSingleObject(collectionParam, executorMethodName, sqlCommandType);
      }
    }
  }

  private void markSingleObject(Object parameter, String executorMethodName,
      SqlCommandType sqlCommandType) {
    if (parameter instanceof Auditable) {
      Auditable auditableEntity = (Auditable) parameter;
      if (isInsertCommand(executorMethodName, sqlCommandType)) {
        auditingHandler.markCreated(auditableEntity);
      } else if (isUpdateCommand(executorMethodName, sqlCommandType)) {
        auditingHandler.markModified(auditableEntity);
      }
    }

    if (isUpdateCommand(executorMethodName, sqlCommandType)) {
      if (parameter instanceof SoftDeletable) {
        SoftDeletable softDeletableEntity = (SoftDeletable) parameter;
        softDeletingHandler.markDeleted(softDeletableEntity);
      }
    }
  }

  private boolean isInsertCommand(String executorMethodName, SqlCommandType sqlCommandType) {
    return "update".equals(executorMethodName) && sqlCommandType.equals(SqlCommandType.INSERT);
  }

  private boolean isUpdateCommand(String executorMethodName, SqlCommandType sqlCommandType) {
    return "update".equals(executorMethodName) && sqlCommandType.equals(SqlCommandType.UPDATE);
  }

  private boolean isDeleteCommand(String executorMethodName, SqlCommandType sqlCommandType) {
    return "update".equals(executorMethodName) && sqlCommandType.equals(SqlCommandType.DELETE);
  }

  private boolean isSelectCommand(String executorMethodName) {
    return "query".equals(executorMethodName);
  }

}
