package com.lsitc.global.auditing;

import org.springframework.stereotype.Component;

@Component
public class SoftDeletingHandler {

  private DateTimeProvider dateTimeProvider = CurrentDateTimeProvider.INSTANCE;
  private UserProvider userProvider = CurrentUserEntityProvider.INSTANCE;

  public <T extends SoftDeletable> void markDeleted(T target) {
    this.touchDeleted(target);
  }

  private <T extends SoftDeletable> void touchDeleted(T softDeletable) {
    if (softDeletable.isDeleted()) {
      softDeletable.setDeletedBy(userProvider.getId());
      softDeletable.setDeletedDate(dateTimeProvider.getNow());
    }
  }
}
