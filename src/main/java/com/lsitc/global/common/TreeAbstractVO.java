package com.lsitc.global.common;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;

@Getter
public abstract class TreeAbstractVO {
  private List<TreeAbstractVO> items = new ArrayList<TreeAbstractVO>();
  private Integer level = 1;

  public abstract Long id();

  public abstract Long parentsId();

  public void addChild(TreeAbstractVO child) {
    child.addLevel(this.level);
    this.items.add(child);
  }

  private void addLevel(int parentsLevel) {
    this.level = parentsLevel + 1;
    this.items.forEach(vo -> {
      vo.addLevel(this.level);
    });
  }

}
