package com.lsitc.global.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import com.lsitc.global.common.TreeAbstractVO;

public class TreeUtils {

  public static <T extends TreeAbstractVO> List<T> getTree(List<T> list){
    Map<Long, TreeAbstractVO> idMap =
        list.stream().collect(Collectors.toMap(TreeAbstractVO::id, Function.identity()));
    
    List<T> reulstList = new ArrayList<T>();
    
    list.forEach(vo -> {
      if (vo.parentsId() == null) {
        reulstList.add(vo);
      } else {
        idMap.get(vo.parentsId()).addChild(vo);
      }
    });

    return reulstList;
  }

}
