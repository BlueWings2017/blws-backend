package com.lsitc.domain.common.bloc.dao;

import com.lsitc.domain.common.bloc.entity.BlocEntity;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface BlocDAO {

  BlocEntity selectBlocById(BlocEntity blocEntity);

  List<BlocEntity> selectAll();

  int insertBloc(BlocEntity blocEntity);

  int updateBlocById(BlocEntity blocEntity);

  int insertBlocWithId(BlocEntity blocEntity);

  int updateBlocIsDeletedById(BlocEntity blocEntity);
}
