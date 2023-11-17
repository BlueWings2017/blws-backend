package com.lsitc.domain.common.bloc.service;

import com.lsitc.domain.common.bloc.dao.BlocDAO;
import com.lsitc.domain.common.bloc.entity.BlocEntity;
import com.lsitc.domain.common.bloc.exception.BlocException;
import com.lsitc.domain.common.bloc.vo.BlocAddRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocAddResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocInfoGetRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocInfoGetResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocListGetResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocModifyRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocModifyResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocRemoveRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocRemoveResponseVO;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@AllArgsConstructor
public class BlocService {

  private final BlocDAO blocDAO;

  public BlocInfoGetResponseVO getBlocInfo(final BlocInfoGetRequestVO blocInfoGetRequestVO) {
    BlocEntity blocEntity = blocInfoGetRequestVO.toEntity();
    log.info(blocEntity.toString());
    BlocEntity blocInfo = blocDAO.selectBlocById(blocEntity);
    return BlocInfoGetResponseVO.of(blocInfo);
  }

  public List<BlocListGetResponseVO> getBlocList() {
    List<BlocEntity> blocEntityList = blocDAO.selectAll();
    return blocEntityList.stream().map(BlocListGetResponseVO::of).collect(Collectors.toList());
  }

  public BlocAddResponseVO addBloc(final BlocAddRequestVO blocAddRequestVO) {
    BlocEntity blocEntity = blocAddRequestVO.toEntity();
    log.info(blocEntity.toString());
    int addRows = blocDAO.insertBloc(blocEntity);
    return BlocAddResponseVO.of(addRows);
  }

  public BlocModifyResponseVO modifyBloc(final BlocModifyRequestVO blocModifyRequestVO) {
    BlocEntity blocEntity = blocModifyRequestVO.toEntity();
    int upsertRows = upsertBloc(blocEntity);
    log.info(blocEntity.toString());
    return BlocModifyResponseVO.of(upsertRows);
  }

  private int upsertBloc(BlocEntity targetEntity) {
    BlocEntity blocEntity = blocDAO.selectBlocById(targetEntity);
    return blocEntity != null ? blocDAO.updateBlocById(targetEntity)
        : blocDAO.insertBlocWithId(targetEntity);
  }

  public BlocRemoveResponseVO removeBloc(final BlocRemoveRequestVO blocRemoveRequestVO)
      throws BlocException {
    BlocEntity blocEntity = blocDAO.selectBlocById(blocRemoveRequestVO.toEntity());
    if (blocEntity == null) {
      throw new BlocException("blocEntity is null");
    }
    blocEntity.delete();
    log.info(blocEntity.toString());
    int deleteRows = blocDAO.updateBlocIsDeletedById(blocEntity);
    return BlocRemoveResponseVO.of(deleteRows);
  }
}
