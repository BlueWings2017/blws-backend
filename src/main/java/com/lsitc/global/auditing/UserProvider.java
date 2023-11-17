package com.lsitc.global.auditing;

public interface UserProvider<T, ID> {

  T getUser();

  ID getId();
}
