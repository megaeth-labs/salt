#!/bin/bash
# timetrace_simple_statistics.sh - 简化版批量统计（无颜色输出）

# ==================== 配置参数 ====================
INPUT_FILE="${1}"
START_THREAD="${2}"
START_EVENT_PATTERN="${3}"
END_THREAD="${4}"
END_EVENT_PATTERN="${5}"

# ==================== 辅助函数 ====================
log_error() {
    echo "[ERROR] $1" >&2
}

# 从时间字符串提取纳秒值
extract_ns() {
    echo "$1" | grep -oE '[0-9]+\.[0-9]+' | head -1
}

# 打印帮助信息
print_help() {
    echo "Timetrace简化统计工具"
    echo ""
    echo "用法: $0 <输入文件> <开始线程> <开始事件> <结束线程> <结束事件>"
    echo ""
    echo "示例:"
    echo "  $0 timetrace.log T1 'update fin started' T1 'update fin finished'"
    echo ""
    exit 0
}

# ==================== 主统计函数 ====================
simple_statistics() {
    local input_file="$1"
    local start_thread="$2"
    local start_pattern="$3"
    local end_thread="$4"
    local end_pattern="$5"
    
    # 检查参数
    if [ -z "$input_file" ] || [ -z "$start_thread" ] || [ -z "$start_pattern" ] || [ -z "$end_thread" ] || [ -z "$end_pattern" ]; then
        print_help
    fi
    
    # 检查文件是否存在
    if [ ! -f "$input_file" ]; then
        log_error "输入文件不存在: $input_file"
        exit 1
    fi
    
    # 检查bc是否安装
    if ! command -v bc &> /dev/null; then
        log_error "需要安装bc命令: sudo apt-get install bc"
        exit 1
    fi
    
    echo "========================================"
    echo "      Timetrace统计结果      "
    echo "========================================"
    echo ""
    echo "查询条件:"
    echo "  开始事件: $start_thread - '$start_pattern'"
    echo "  结束事件: $end_thread - '$end_pattern'"
    echo ""
    
    # ==================== 1. 查找所有开始事件 ====================
    # 获取所有开始事件的行号和内容
    declare -a start_lines
    declare -a start_times
    declare -a start_line_nums
    
    local line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))
        
        # 检查是否匹配开始事件
        if [[ "$line" =~ ^$start_thread.*$start_pattern ]]; then
            start_lines+=("$line")
            start_times+=("$(extract_ns "$line")")
            start_line_nums+=("$line_num")
        fi
    done < "$input_file"
    
    local start_count=${#start_lines[@]}
    
    if [ $start_count -eq 0 ]; then
        log_error "未找到开始事件: $start_thread - '$start_pattern'"
        exit 1
    fi
    
    # ==================== 2. 查找所有结束事件 ====================
    # 获取所有结束事件的行号和内容
    declare -a end_lines
    declare -a end_times
    declare -a end_line_nums
    
    line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))
        
        # 检查是否匹配结束事件
        if [[ "$line" =~ ^$end_thread.*$end_pattern ]]; then
            end_lines+=("$line")
            end_times+=("$(extract_ns "$line")")
            end_line_nums+=("$line_num")
        fi
    done < "$input_file"
    
    local end_count=${#end_lines[@]}
    
    if [ $end_count -eq 0 ]; then
        log_error "未找到结束事件: $end_thread - '$end_pattern'"
        exit 1
    fi
    
    # ==================== 3. 配对并计算耗时 ====================
    declare -a durations_ns
    declare -a pairs_info
    
    # 使用标记数组避免重复匹配
    declare -a end_used
    for ((i=0; i<end_count; i++)); do
        end_used[$i]=0
    done
    
    # 对于每个开始事件，寻找对应的结束事件
    for ((i=0; i<start_count; i++)); do
        local start_time="${start_times[i]}"
        local start_line_num="${start_line_nums[i]}"
        local start_line="${start_lines[i]}"
        
        # 找到在开始事件之后且未使用的最早的结束事件
        local matched_end_index=-1
        local earliest_line_num=9999999
        
        for ((j=0; j<end_count; j++)); do
            # 如果这个结束事件已经被使用过，跳过
            if [ "${end_used[$j]}" -eq 1 ]; then
                continue
            fi
            
            local end_line_num="${end_line_nums[$j]}"
            local end_time="${end_times[$j]}"
            
            # 结束事件必须在开始事件之后
            if [ "$end_line_num" -gt "$start_line_num" ] && [ $(echo "$end_time > $start_time" | bc) -eq 1 ]; then
                # 找到最早的一个结束事件
                if [ "$end_line_num" -lt "$earliest_line_num" ]; then
                    matched_end_index=$j
                    earliest_line_num=$end_line_num
                fi
            fi
        done
        
        if [ $matched_end_index -eq -1 ]; then
            # 如果没找到，跳过这个开始事件
            continue
        fi
        
        # 标记这个结束事件为已使用
        end_used[$matched_end_index]=1
        
        local end_time="${end_times[$matched_end_index]}"
        local end_line="${end_lines[$matched_end_index]}"
        local end_line_num="${end_line_nums[$matched_end_index]}"
        
        # 计算耗时
        local duration_ns=$(echo "$end_time - $start_time" | bc)
        durations_ns+=("$duration_ns")
        
        # 保存完整的配对信息
        pairs_info+=("$start_time|$end_time|$duration_ns|$start_line|$end_line")
    done
    
    local pair_count=${#durations_ns[@]}
    
    if [ $pair_count -eq 0 ]; then
        log_error "未成功配对任何事件"
        exit 1
    fi
    
    # ==================== 4. 输出每组耗时 ====================
    echo "=== 详细耗时 ($pair_count 组) ==="
    echo ""
    
    for ((i=0; i<pair_count; i++)); do
        IFS='|' read -r start_time end_time duration_ns start_line end_line <<< "${pairs_info[i]}"
        
        # 转换为毫秒
        duration_ms=$(echo "scale=3; $duration_ns / 1000000" | bc)
        
        echo "第 $((i+1)) 组:"
        echo "开始: $start_line"
        echo "结束: $end_line"
        echo "耗时: ${duration_ns} ns (${duration_ms} ms)"
        echo ""
    done
    
    # ==================== 5. 计算统计信息 ====================
    # 计算总和
    local sum_ns=0
    for duration in "${durations_ns[@]}"; do
        sum_ns=$(echo "$sum_ns + $duration" | bc)
    done
    
    # 计算平均值
    local avg_ns=$(echo "scale=3; $sum_ns / $pair_count" | bc)
    local avg_ms=$(echo "scale=6; $avg_ns / 1000000" | bc)
    
    # 找出最大值和最小值
    local max_ns=${durations_ns[0]}
    local min_ns=${durations_ns[0]}
    local max_index=0
    local min_index=0
    
    for ((i=1; i<pair_count; i++)); do
        local current="${durations_ns[i]}"
        
        if [ $(echo "$current > $max_ns" | bc) -eq 1 ]; then
            max_ns="$current"
            max_index=$i
        fi
        
        if [ $(echo "$current < $min_ns" | bc) -eq 1 ]; then
            min_ns="$current"
            min_index=$i
        fi
    done
    
    local max_ms=$(echo "scale=3; $max_ns / 1000000" | bc)
    local min_ms=$(echo "scale=3; $min_ns / 1000000" | bc)
    
    # ==================== 6. 输出统计摘要 ====================
    echo "=== 统计摘要 ==="
    echo ""
    echo "总组数: $pair_count"
    echo ""
    
    # 获取最小组和最大组的详细信息
    IFS='|' read -r min_start_time min_end_time min_duration_ns min_start_line min_end_line <<< "${pairs_info[min_index]}"
    IFS='|' read -r max_start_time max_end_time max_duration_ns max_start_line max_end_line <<< "${pairs_info[max_index]}"
    
    echo "最大值 (第 $((max_index+1)) 组):"
    echo "  耗时: ${max_ns} ns (${max_ms} ms)"
    echo "  开始: $max_start_line"
    echo "  结束: $max_end_line"
    echo ""
    
    echo "最小值 (第 $((min_index+1)) 组):"
    echo "  耗时: ${min_ns} ns (${min_ms} ms)"
    echo "  开始: $min_start_line"
    echo "  结束: $min_end_line"
    echo ""
    
    echo "平均值:"
    echo "  耗时: ${avg_ns} ns (${avg_ms} ms)"
    echo ""
    
    # 计算总耗时
    local total_ms=$(echo "scale=3; $sum_ns / 1000000" | bc)
    echo "总耗时:"
    echo "  累计: ${sum_ns} ns (${total_ms} ms)"
    echo ""
    
    # ==================== 7. 输出汇总信息 ====================
    echo "=== 汇总信息 ==="
    echo ""
    echo "开始事件总数: $start_count"
    echo "结束事件总数: $end_count"
    echo "成功配对数: $pair_count"
    
    local unused_starts=$((start_count - pair_count))
    if [ $unused_starts -gt 0 ]; then
        echo "未配对的开始事件: $unused_starts"
    fi
    
    local used_ends=0
    for ((i=0; i<end_count; i++)); do
        if [ "${end_used[$i]}" -eq 1 ]; then
            used_ends=$((used_ends + 1))
        fi
    done
    
    local unused_ends=$((end_count - used_ends))
    if [ $unused_ends -gt 0 ]; then
        echo "未使用的结束事件: $unused_ends"
    fi
    
    echo ""
    echo "========================================"
}

# ==================== 主执行流程 ====================
main() {
    # 检查参数
    if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ $# -lt 5 ]; then
        print_help
    fi
    
    # 执行统计
    simple_statistics "$@"
}

# 执行主函数
main "$@"