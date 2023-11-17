package com.lsitc.domain.common.code.dao;

import com.lsitc.domain.common.code.entity.GroupCodeEntity;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface GroupCodeDAO {

  GroupCodeEntity selectGroupCodeById(GroupCodeEntity groupCodeEntity);

  List<GroupCodeEntity> selectGroupCodeByConditions(GroupCodeEntity groupCodeEntity);

  int updateGroupCodeById(GroupCodeEntity groupCodeEntity);

  int insertGroupCodeWithId(GroupCodeEntity groupCodeEntity);

  int insertGroupCode(List<GroupCodeEntity> groupCodeEntityList);

  int deleteGroupCodeById(List<GroupCodeEntity> groupCodeEntityList);
}
