package com.lsitc.global.auditing;

import org.springframework.stereotype.Component;

@Component
public class AuditingHandler {

  private DateTimeProvider dateTimeProvider = CurrentDateTimeProvider.INSTANCE;
  private UserProvider userProvider = CurrentUserEntityProvider.INSTANCE;

  public <T extends Auditable> void markCreated(T target) {
    this.touch(target, true);
  }

  public <T extends Auditable> void markModified(T target) {
    this.touch(target, false);
  }

  private <T extends Auditable> void touch(T target, boolean isNew) {
    this.touchAuditor(target, isNew);
    this.touchDate(target, isNew);
  }

  private <T extends Auditable> void touchAuditor(T auditable, boolean isNew) {
    if (isNew) {
      auditable.setCreatedBy(userProvider.getId());
    }
    auditable.setLastModifiedBy(userProvider.getId());
  }

  private <T extends Auditable> void touchDate(T auditable, boolean isNew) {
    if (isNew) {
      auditable.setCreatedDate(dateTimeProvider.getNow());
    }
    auditable.setLastModifiedDate(dateTimeProvider.getNow());
  }
}
