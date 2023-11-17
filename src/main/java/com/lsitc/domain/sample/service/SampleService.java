package com.lsitc.domain.sample.service;

import com.lsitc.domain.sample.dao.SampleDAO;
import com.lsitc.domain.sample.entity.SampleEntity;
import com.lsitc.domain.sample.exception.SampleException;
import com.lsitc.domain.sample.vo.SampleAddRequestVO;
import com.lsitc.domain.sample.vo.SampleAddResponseVO;
import com.lsitc.domain.sample.vo.SampleInfoGetRequestVO;
import com.lsitc.domain.sample.vo.SampleInfoGetResponseVO;
import com.lsitc.domain.sample.vo.SampleListGetResponseVO;
import com.lsitc.domain.sample.vo.SampleModifyRequestVO;
import com.lsitc.domain.sample.vo.SampleModifyResponseVO;
import com.lsitc.domain.sample.vo.SampleRemoveRequestVO;
import com.lsitc.domain.sample.vo.SampleRemoveResponseVO;
import com.lsitc.global.paging.Pageable;
import com.lsitc.global.util.FileUtils;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@Service
@AllArgsConstructor
public class SampleService {

  private final SampleDAO sampleDAO;

  public SampleInfoGetResponseVO getSampleInfo(
      final SampleInfoGetRequestVO sampleInfoGetRequestVO) {
    SampleEntity sampleEntity = sampleInfoGetRequestVO.toEntity();
    log.info(sampleEntity.toString());
    SampleEntity resultEntity = sampleDAO.selectSampleById(sampleEntity);
    return SampleInfoGetResponseVO.of(resultEntity);
  }

  public List<SampleListGetResponseVO> getSampleList(final Pageable pageable) {
    List<SampleEntity> resultEntityList = sampleDAO.selectAll(pageable);
    return resultEntityList.stream().map(SampleListGetResponseVO::of).collect(Collectors.toList());
  }

  @Transactional
  public SampleAddResponseVO addSample(final List<SampleAddRequestVO> sampleAddRequestVO) {
    List<SampleEntity> sampleEntityList = sampleAddRequestVO.stream()
        .map(SampleAddRequestVO::toEntity).collect(Collectors.toList());
    log.info(sampleEntityList.toString());

    if (sampleEntityList.size() == 1) {
      sampleDAO.insertSample(sampleEntityList.get(0));
      log.info("sample entity id: {}", sampleEntityList.get(0).getId());
      return SampleAddResponseVO.of(sampleEntityList.get(0).getId());
    } else {
      int addRows = sampleDAO.insertSampleList(sampleEntityList);
      return SampleAddResponseVO.of(addRows);
    }
  }

  @Transactional
  public SampleModifyResponseVO modifySample(
      final List<SampleModifyRequestVO> sampleModifyRequestVO) {
    List<SampleEntity> sampleEntityList = sampleModifyRequestVO.stream()
        .map(SampleModifyRequestVO::toEntity).collect(Collectors.toList());
    log.info(sampleEntityList.toString());

    List<SampleEntity> updateList = new ArrayList<>();
    List<SampleEntity> insertList = new ArrayList<>();
    sampleEntityList.forEach(sampleEntity -> {
      if (isUpdate(sampleEntity)) {
        updateList.add(sampleEntity);
      } else {
        insertList.add(sampleEntity);
      }
    });

    int upsertRows = (updateList.size() > 0 ? sampleDAO.updateSampleById(updateList) : 0)
        + (insertList.size() > 0 ? sampleDAO.insertSampleWithId(insertList) : 0);
    return SampleModifyResponseVO.of(upsertRows);
  }

  private boolean isUpdate(SampleEntity targetEntity) {
    return sampleDAO.selectSampleById(targetEntity) != null;
  }

  @Transactional
  public SampleRemoveResponseVO removeSample(SampleRemoveRequestVO sampleRemoveRequestVO) {
    SampleEntity sampleEntity = sampleRemoveRequestVO.toEntity();
    log.info(sampleEntity.toString());
//    int deleteRows = hardDeleteSample(sampleEntity);
    int deleteRows = softDeleteSample(sampleEntity);
    return SampleRemoveResponseVO.of(deleteRows);
  }

  @Transactional
  public SampleRemoveResponseVO removeSample(List<SampleRemoveRequestVO> sampleRemoveRequestVO) {
    List<SampleEntity> sampleEntityList = sampleRemoveRequestVO.stream()
        .map(SampleRemoveRequestVO::toEntity).collect(Collectors.toList());
    log.info(sampleEntityList.toString());
//    int deleteRows = hardDeleteSample(sampleEntityList);
    int deleteRows = softDeleteSample(sampleEntityList);
    return SampleRemoveResponseVO.of(deleteRows);
  }

  private int hardDeleteSample(SampleEntity targetEntity) {
    return sampleDAO.deleteSampleById(Collections.singletonList(targetEntity));
  }

  private int hardDeleteSample(List<SampleEntity> targetEntityList) {
    return sampleDAO.deleteSampleById(targetEntityList);
  }

  private int softDeleteSample(SampleEntity targetEntity) {
    return softDeleteSample(Collections.singletonList(targetEntity));
  }

  private int softDeleteSample(List<SampleEntity> targetEntityList) {
    List<SampleEntity> sampleEntityList = sampleDAO.selectSampleByIds(targetEntityList);
    if (sampleEntityList.isEmpty()) {
      throw new SampleException("sampleEntity is not exist");
    }
    sampleEntityList.forEach(SampleEntity::delete);
    log.info(sampleEntityList.toString());
    return sampleDAO.updateSampleIsDeletedById(sampleEntityList);
  }

  public void uploadSampleFiles(MultipartFile[] files) {
    for (MultipartFile file : files) {
      uploadSampleFile(file);
    }
  }

  public void uploadSampleFile(MultipartFile file) {
    String path = "tmp/files/tmp";
    String originalFilename = getOriginalFilename(file);
    String filename = UUID.randomUUID().toString();
    String extension = FileUtils.getExtension(originalFilename);

    try {
      File targetFile = new File(path + File.separator + originalFilename);
      FileUtils.touch(targetFile);
      file.transferTo(targetFile);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private String getOriginalFilename(MultipartFile file) {
    return Optional.ofNullable(file.getOriginalFilename()).filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new SampleException("Filename is empty"));
  }

  public File downloadSampleFiles(List<String> filenames) {
    List<File> files = filenames.stream()
        .map(this::downloadSampleFile).collect(Collectors.toList());
    return files.size() > 1 ? FileUtils.compressFiles(files) : files.get(0);
  }

  public File downloadSampleFile(String filename) {
    return getSampleFile(filename);
  }

  private File getSampleFile(String filename) {
    File file = new File(filename);
    String content = RandomStringUtils.randomAlphabetic(10);
    try {
      FileUtils.writeStringToFile(file, content, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return file;
  }

}