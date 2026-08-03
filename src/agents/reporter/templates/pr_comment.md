## CodeGuard 安全分析报告
> 本次扫描：{{ scan_scope }} · {{ file_count }} 个文件 · 安全扫描耗时 {{ security_duration_ms }}ms{% if migration_duration_ms %} · 迁移评估耗时 {{ migration_duration_ms }}ms{% endif %}
{% if degraded %}
> 扫描降级：{{ degraded_reasons | join('; ') }}
{% endif %}

{% if blocking_items %}
### 阻断项 ({{ blocking_items | length }})
| 严重度 | 问题 | 位置 | 修复方案 |
|--------|------|------|----------|
{% for item in blocking_items %}
| {{ item.severity }} | [{{ item.id }}] {{ item.description }} [{{ item.source }}] | {{ item.location }} | {{ item.fix }}{% if item.appealable %} · [申请豁免]({{ item.appeal_url }}){% endif %} |
{% endfor %}
{% endif %}

{% if warning_items %}
### 建议项 ({{ warning_items | length }})
{% if security_warnings %}
#### 安全建议
{% for item in security_warnings %}
- {{ item.message }}
{% endfor %}
{% endif %}
{% if migration_warnings %}
#### 迁移建议
{% for item in migration_warnings %}
- {{ item.change_desc }}：影响 `{{ item.location }}` → [修复建议]({{ item.ref_url }})
{% endfor %}
{% endif %}
{% endif %}

{% if pass_items %}
### 通过项
{% for item in pass_items %}
- {{ item }}
{% endfor %}
{% endif %}

---
[查看完整报告]({{ full_report_url }}) · [管理豁免规则]({{ rules_url }})
