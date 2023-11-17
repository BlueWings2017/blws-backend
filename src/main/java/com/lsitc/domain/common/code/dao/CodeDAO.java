package com.lsitc.domain.common.code.dao;

import com.lsitc.domain.common.code.entity.CodeEntity;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CodeDAO {

  CodeEntity selectCodeById(CodeEntity codeEntity);

  List<CodeEntity> selectCodeByConditions(CodeEntity codeEntity);

  int insertCode(List<CodeEntity> codeEntityList);

  int insertCodeWithId(List<CodeEntity> codeEntityList);

  int updateCodeById(List<CodeEntity> codeEntityList);

  int deleteCodeById(List<CodeEntity> codeEntityList);
}
