"""一键修复任务。

针对 QQ 小程序重复登录等异常，通过点击右上角菜单 → 一键修复 → 确认，
尝试恢复游戏状态。
"""

from __future__ import annotations

from loguru import logger

from core.engine.task.registry import TaskResult
from tasks.base import TaskBase


class TaskRepair(TaskBase):
    """封装 `TaskRepair` 任务的执行入口与步骤。"""

    # 整窗模板匹配 btn_menu.png 的 ROI（右上顶部 40px）。
    _MENU_TEMPLATE = 'btn_menu.png'
    _MENU_THRESHOLD = 0.8
    _MENU_TOP_PX = 40
    _MENU_ROI_REL = (0.55, 0.0, 1.0, 1.0)

    # 等待菜单展开与弹窗出现的时间（秒）。
    _PRE_WAIT_SECONDS = 1.0
    _POST_WAIT_SECONDS = 1.0
    _CONFIRM_WAIT_SECONDS = 1.0

    def _interruptible_sleep(self, seconds: float) -> bool:
        """可中断睡眠，返回 True 表示未取消；False 表示已请求停止。"""
        return bool(self.engine.device.sleep(max(0.0, seconds)))

    def run(self, rect: tuple[int, int, int, int]) -> TaskResult:
        """执行一键修复任务并返回调度结果。"""
        _ = rect
        platform_value = self.config.planting.window_platform.value
        if platform_value != 'qq':
            logger.warning(f'一键修复: 当前平台={platform_value}，仅支持 QQ 平台，跳过执行')
            return self.ok()

        logger.info('一键修复: 开始')
        if not self._repair():
            logger.error('一键修复: 执行失败')
            return TaskResult(success=False, error='一键修复执行失败')

        logger.info('一键修复: 完成')
        return self.ok()

    def _repair(self) -> bool:
        """执行菜单 → 一键修复 → 确认流程。"""
        engine = self.engine

        # 1. 点击右上角三点菜单（整窗模板匹配，后台点击）。
        logger.info('一键修复: 点击右上角菜单')
        if not engine._click_template_on_full_window(
            self._MENU_TEMPLATE,
            roi_rel=self._MENU_ROI_REL,
            top_px=self._MENU_TOP_PX,
            threshold=self._MENU_THRESHOLD,
            desc='repair_top_menu',
        ):
            logger.error('一键修复: 点击右上角菜单失败')
            return False
        if not self._interruptible_sleep(self._PRE_WAIT_SECONDS):
            logger.warning('一键修复: 等待期间收到停止请求')
            return False

        # 2. 调用“一键修复”。
        logger.info('一键修复: 调用“一键修复”')
        uia_root = engine._find_uia_window_by_hwnd(engine.window_manager.get_window_handle())
        if uia_root is None:
            logger.error('一键修复: 无法获取 UIA 窗口根元素')
            return False
        if not engine._click_uia_element_by_name(uia_root, '一键修复', desc='repair_one_click_repair'):
            logger.error('一键修复: 调用“一键修复”未成功')
            return False
        if not self._interruptible_sleep(self._POST_WAIT_SECONDS):
            logger.warning('一键修复: 等待期间收到停止请求')
            return False

        # 3. 调用“确认”。
        logger.info('一键修复: 调用“确认”')
        uia_root = engine._find_uia_window_by_hwnd(engine.window_manager.get_window_handle())
        if uia_root is None:
            logger.error('一键修复: 无法获取 UIA 窗口根元素')
            return False
        if not engine._click_uia_element_by_name(uia_root, '确认', desc='repair_confirm'):
            logger.error('一键修复: 调用“确认”未成功')
            return False
        if not self._interruptible_sleep(self._CONFIRM_WAIT_SECONDS):
            logger.warning('一键修复: 等待期间收到停止请求')
            return False

        return True
