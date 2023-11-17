package com.lsitc.domain.common.code.service;

import com.lsitc.domain.common.code.dao.CodeDAO;
import com.lsitc.domain.common.code.dao.GroupCodeDAO;
import com.lsitc.domain.common.code.entity.CodeEntity;
import com.lsitc.domain.common.code.entity.GroupCodeEntity;
import com.lsitc.domain.common.code.exception.CodeException;
import com.lsitc.domain.common.code.vo.CodeAddRequestVO;
import com.lsitc.domain.common.code.vo.CodeAddResponseVO;
import com.lsitc.domain.common.code.vo.CodeListSearchRequestVO;
import com.lsitc.domain.common.code.vo.CodeListSearchResponseVO;
import com.lsitc.domain.common.code.vo.CodeModifyRequestVO;
import com.lsitc.domain.common.code.vo.CodeModifyResponseVO;
import com.lsitc.domain.common.code.vo.CodeRemoveRequestVO;
import com.lsitc.domain.common.code.vo.CodeRemoveResponseVO;
import com.lsitc.domain.common.code.vo.GroupCodeAddRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeAddResponseVO;
import com.lsitc.domain.common.code.vo.GroupCodeListSearchRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeListSearchResponseVO;
import com.lsitc.domain.common.code.vo.GroupCodeModifyRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeModifyResponseVO;
import com.lsitc.domain.common.code.vo.GroupCodeRemoveRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeRemoveResponseVO;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@AllArgsConstructor
public class CodeService {

  private final GroupCodeDAO groupCodeDAO;
  private final CodeDAO codeDAO;

  public List<GroupCodeListSearchResponseVO> searchGroupCodeList(
      final GroupCodeListSearchRequestVO groupCodeListSearchRequestVO) {
    GroupCodeEntity groupCodeEntity = groupCodeListSearchRequestVO.toEntity();
    log.info(groupCodeEntity.toString());
    List<GroupCodeEntity> groupCodeEntityList = groupCodeDAO.selectGroupCodeByConditions(
        groupCodeEntity);
    return groupCodeEntityList.stream().map(GroupCodeListSearchResponseVO::of)
        .collect(Collectors.toList());
  }

  public List<CodeListSearchResponseVO> searchCodeList(
      final CodeListSearchRequestVO codeListSearchRequestVO) {
    CodeEntity codeEntity = codeListSearchRequestVO.toEntity();
    log.info(codeEntity.toString());
    List<CodeEntity> codeEntityList = codeDAO.selectCodeByConditions(codeEntity);
    GroupCodeEntity groupCodeEntity = groupCodeDAO.selectGroupCodeById(
        GroupCodeEntity.builder().id(codeEntity.getGroupCodeId()).build());
    return codeEntityList.stream()
        .map(entity -> CodeListSearchResponseVO.of(entity, groupCodeEntity))
        .collect(Collectors.toList());
  }

  @Transactional
  public GroupCodeAddResponseVO addGroupCode(
      final List<GroupCodeAddRequestVO> groupCodeAddRequestVOList) {
    List<GroupCodeEntity> groupCodeEntityList =
        groupCodeAddRequestVOList.stream()
            .map(GroupCodeAddRequestVO::toEntity)
            .collect(Collectors.toList());
    int addRows = groupCodeDAO.insertGroupCode(groupCodeEntityList);
    return GroupCodeAddResponseVO.of(addRows);
  }

  @Transactional
  public CodeAddResponseVO addCode(
      final List<CodeAddRequestVO> codeAddRequestVOList) {
    List<CodeEntity> codeEntityList = codeAddRequestVOList.stream()
        .map(CodeAddRequestVO::toEntity)
        .collect(Collectors.toList());
    int addRows = codeDAO.insertCode(codeEntityList);
    return CodeAddResponseVO.of(addRows);
  }

  @Transactional
  public GroupCodeModifyResponseVO modifyGroupCode(
      final List<GroupCodeModifyRequestVO> groupCodeModifyRequestVOList) {
    List<GroupCodeEntity> groupCodeEntityList =
        groupCodeModifyRequestVOList.stream().map(GroupCodeModifyRequestVO::toEntity)
            .collect(Collectors.toList());
    int upsertRows = groupCodeEntityList.stream().map(this::upsertGroupCode).mapToInt(i -> i).sum();
    if (upsertRows != groupCodeEntityList.size()) {
      throw new CodeException("Upsert 오류");
    }
    return GroupCodeModifyResponseVO.of(upsertRows);
  }

  private int upsertGroupCode(GroupCodeEntity targetEntity) {
    GroupCodeEntity groupCodeEntity = groupCodeDAO.selectGroupCodeById(targetEntity);
    return groupCodeEntity != null ? groupCodeDAO.updateGroupCodeById(targetEntity)
        : groupCodeDAO.insertGroupCodeWithId(targetEntity);
  }

  @Transactional
  public CodeModifyResponseVO modifyCode(final List<CodeModifyRequestVO> codeModifyRequestVOList) {
    List<CodeEntity> codeEntityList = codeModifyRequestVOList.stream()
        .map(CodeModifyRequestVO::toEntity).collect(Collectors.toList());
    log.info(codeEntityList.toString());

    List<CodeEntity> updateList = new ArrayList<>();
    List<CodeEntity> insertList = new ArrayList<>();
    codeEntityList.forEach(codeEntity -> {
      if (existsCode(codeEntity)) {
        updateList.add(codeEntity);
      } else {
        insertList.add(codeEntity);
      }
    });

    int upsertRows = (updateList.size() > 0 ? codeDAO.updateCodeById(updateList) : 0)
        + (insertList.size() > 0 ? codeDAO.insertCodeWithId(insertList) : 0);
    return CodeModifyResponseVO.of(upsertRows);
  }

  private boolean existsCode(CodeEntity targetEntity) {
    return codeDAO.selectCodeById(targetEntity) != null;
  }

  @Transactional
  public GroupCodeRemoveResponseVO removeGroupCode(
      final List<GroupCodeRemoveRequestVO> groupCodeRemoveRequestVOList) {
    List<GroupCodeEntity> groupCodeEntityList =
        groupCodeRemoveRequestVOList.stream().map(GroupCodeRemoveRequestVO::toEntity)
            .collect(Collectors.toList());
    if (groupCodeEntityList.size() < 1) {
      throw new CodeException("Parameter is empty");
    }
    int deleteRows = groupCodeDAO.deleteGroupCodeById(groupCodeEntityList);
    return GroupCodeRemoveResponseVO.of(deleteRows);
  }

  @Transactional
  public CodeRemoveResponseVO removeCode(final List<CodeRemoveRequestVO> codeRemoveRequestVOList) {
    List<CodeEntity> codeEntityList =
        codeRemoveRequestVOList.stream().map(CodeRemoveRequestVO::toEntity)
            .collect(Collectors.toList());
    if (codeEntityList.size() < 1) {
      throw new CodeException("Parameter is empty");
    }
    int deleteRows = codeDAO.deleteCodeById(codeEntityList);
    return CodeRemoveResponseVO.of(deleteRows);
  }
}
