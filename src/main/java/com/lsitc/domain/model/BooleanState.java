package com.lsitc.domain.model;

public enum BooleanState {
  TRUE("1", true),
  FALSE("0", false),
  NULL("", null);

  private String stringValue;
  private Boolean booleanValue;

  BooleanState(String stringValue, Boolean booleanValue) {
    this.stringValue = stringValue;
    this.booleanValue = booleanValue;
  }

  public String getStringValue() {
    return stringValue;
  }

  public Boolean getBooleanValue() {
    return booleanValue;
  }

  public static BooleanState of(String stringValue){
    for (BooleanState booleanState : values()){
      if (booleanState.stringValue.equals(stringValue))
        return booleanState;
    }
    return NULL;
  }

  public static BooleanState of(Boolean booleanValue){
    for (BooleanState booleanState : values()){
      if (booleanState.booleanValue.equals(booleanValue))
        return booleanState;
    }
    return NULL;
  }
}
