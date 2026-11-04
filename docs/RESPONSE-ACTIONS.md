# 处置动作对象

response_actions 将每个事件的处置过程独立保存为可审计对象。状态只能按以下顺序流转：

draft → pending_approval → approved → executing → succeeded|failed → verified

succeeded 或 failed 可以先进入 rolled_back，再记录 verified。每次状态变更都保存责任人和时间；执行回执、回滚方案和恢复验证是独立字段。客户端只记录计划与人工回执，不会凭借报告按钮直接封禁、删除或执行客户主机命令。

前端 IPC：

- get_response_actions(caseId)
- create_response_action(action)
- update_response_action_status(actionId, status, actor, detail)
- record_response_receipt(actionId, receipt)
- save_response_rollback_plan(actionId, plan)

报告 HTML 和 DOCX 会把这些对象作为“处置动作、审批与恢复验证”章节导出，明确区分待审批、已执行和待验证。
