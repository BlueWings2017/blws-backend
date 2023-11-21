package com.blws.global.auditing;

public interface UserProvider<T, ID> {

  T getUser();

  ID getId();
}
