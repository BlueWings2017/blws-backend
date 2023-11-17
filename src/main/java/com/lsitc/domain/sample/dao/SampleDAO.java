package com.lsitc.domain.sample.dao;

import com.lsitc.domain.sample.entity.SampleEntity;
import com.lsitc.global.paging.Pageable;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface SampleDAO {

  SampleEntity selectSampleById(SampleEntity sampleEntity);

  List<SampleEntity> selectSampleByIds(List<SampleEntity> sampleEntityList);

  List<SampleEntity> selectAll();

  List<SampleEntity> selectAll(/*@Param("entity") SampleEntity sampleEntity,*/
      @Param("pageable") Pageable pageable);

  void insertSample(SampleEntity sampleEntity);

  int insertSampleList(List<SampleEntity> sampleEntityList);

  int updateSampleById(List<SampleEntity> sampleEntityList);

  int insertSampleWithId(List<SampleEntity> sampleEntityList);

  int deleteSampleById(List<SampleEntity> sampleEntityList);

  int updateSampleIsDeletedById(List<SampleEntity> sampleEntityList);
}