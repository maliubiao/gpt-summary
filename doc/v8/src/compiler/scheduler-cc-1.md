Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/scheduler.cc`. This is the second of three parts.

Here's a breakdown of the code's key sections and their functions:

1. **`SpecialRPONumberer::ComputeSpecialRPO()`**: This function computes a special Reverse Post Order (RPO) traversal of the basic blocks in the control flow graph. It takes into account loop structures to ensure that loop bodies are laid out contiguously in the RPO.

2. **`SpecialRPONumberer::ComputeLoopInfo()`**: This function identifies the loops in the control flow graph and determines the members of each loop. It uses back edges in the graph to identify loop headers and then performs a backward traversal to find all blocks belonging to that loop.

3. **`Scheduler::GetCommonDominator()`**: This function finds the common dominator of two basic blocks in the control flow graph. It uses a caching mechanism to speed up lookups for frequently encountered pairs of blocks.

4. **`Scheduler::PropagateImmediateDominators()`**: This function computes the immediate dominator for each basic block in the graph. It iterates through the blocks in RPO and for each block, it finds the common dominator of all its predecessors.

5. **`Scheduler::GenerateDominatorTree()`**: This function initiates the process of building the dominator tree by seeding the start block and then calling `PropagateImmediateDominators`.

6. **`PrepareUsesVisitor::Run()`**: This visitor class iterates through the nodes of the graph, initializing their placement (fixed, coupled, or schedulable) and counting the number of unscheduled uses for each node.

7. **`ScheduleEarlyNodeVisitor::Run()`**: This visitor class performs the "schedule early" phase, determining the earliest possible block in the RPO where each node can be scheduled, based on the placement of its inputs.

8. **`ScheduleLateNodeVisitor::Run()`**: This visitor class performs the "schedule late" phase, determining the latest possible block where each node can be scheduled while respecting data dependencies and attempting to hoist nodes out of loops.

I need to synthesize a summary of these functions, considering that this is part 2 of 3.
这是 `v8/src/compiler/scheduler.cc` 源代码的第二部分，主要负责**计算特殊逆后序遍历 (Special Reverse Post Order, Special RPO)**，**计算循环信息**，**构建支配树**，以及**准备节点的使用信息**和**进行早调度和晚调度**。

以下是这部分代码的功能归纳：

1. **特殊逆后序遍历 (Special RPO) 计算：**
   -  `SpecialRPONumberer::ComputeSpecialRPO()` 函数实现了计算 Special RPO 的核心逻辑。Special RPO 是一种特殊的遍历顺序，它将循环体内的基本块连续排列，有助于后续的调度优化。
   -  它使用一个栈来跟踪遍历过程，并利用循环信息来确保循环体被完整地添加到 RPO 中。
   -  该过程会更新基本块的 `rpo_number`，`loop_header`，`loop_end` 和 `loop_depth` 等属性。

2. **循环信息计算：**
   - `SpecialRPONumberer::ComputeLoopInfo()` 函数用于识别控制流图中的循环，并记录每个循环包含的基本块。
   - 它利用控制流图中的回边 (backedge) 来识别循环头，然后通过反向遍历来找到属于该循环的所有基本块。

3. **支配树构建：**
   - `Scheduler::GetCommonDominator()` 函数用于查找两个基本块的最近公共支配节点。它使用了一个缓存来优化查找性能。
   - `Scheduler::PropagateImmediateDominators()` 函数通过遍历 RPO 顺序的基本块，为每个基本块确定其直接支配节点。它会考虑所有前驱节点，并向上遍历支配树直到找到公共支配节点。
   - `Scheduler::GenerateDominatorTree()` 函数作为构建支配树的入口，它首先初始化起始块的支配深度，然后调用 `PropagateImmediateDominators` 来构建完整的支配树。

4. **准备节点使用信息：**
   - `PrepareUsesVisitor` 类用于遍历图中的节点，并计算每个节点的未调度使用次数。这有助于确保在调度节点本身之前，其所有使用者都已被调度。
   - `Scheduler::PrepareUses()` 函数创建并运行 `PrepareUsesVisitor` 来完成此过程。

5. **早调度 (Schedule Early)：**
   - `ScheduleEarlyNodeVisitor` 类用于执行早调度算法。早调度的目标是确定每个节点可以被放置的最早的基本块，以满足所有输入依赖。
   - `Scheduler::ScheduleEarly()` 函数创建并运行 `ScheduleEarlyNodeVisitor`，它会从根节点开始，向下传播最早的调度位置。

6. **晚调度 (Schedule Late)：**
   - `ScheduleLateNodeVisitor` 类用于执行晚调度算法。晚调度的目标是确定每个节点可以被放置的最晚的基本块，同时尝试将节点提升到循环外部以减少重复计算。
   - `ScheduleLateNodeVisitor::VisitNode()` 函数是晚调度的核心，它会计算节点的使用者的公共支配节点，并尝试将节点提升到循环前置头。
   -  `SplitNode()` 函数尝试将纯计算节点复制到其使用者的支配块中，以减少寄存器压力或改善代码局部性。
   - `Scheduler::schedule_queue_` 用于存储待调度的节点。

**与 JavaScript 功能的关系：**

这部分代码直接作用于 V8 编译器的中间表示（IR），并不直接对应到特定的 JavaScript 语法或功能。但是，通过优化代码的调度，它可以间接地影响 JavaScript 代码的执行效率。例如，通过将循环不变量提升到循环外部，可以减少循环内部的重复计算，从而提高 JavaScript 代码的性能。

**代码逻辑推理 (假设输入与输出)：**

假设我们有一个简单的控制流图，包含以下基本块：

```
B0 (entry) -> B1 -> B2 -> B3 (exit)
```

并且 `B2` 是一个循环头，回边指向 `B1`。

**输入:** 这个控制流图的表示。

**输出 (Special RPO):**  `B0`, `B2`, `B1`, `B3` (循环体 `B1` 紧随循环头 `B2`)

**输出 (循环信息):** 循环头：`B2`，循环成员：`B1`，`B2`。

**输出 (支配树):**
- `B0` 的支配节点：无 (根节点)
- `B1` 的支配节点：`B0`
- `B2` 的支配节点：`B0`
- `B3` 的支配节点：`B0`

**假设有节点 `n` 在 `B1` 中被定义，并在 `B2` 和 `B3` 中被使用：**

**输出 (早调度):**  节点 `n` 的最早调度位置可能是 `B1` (在其被定义的块中)。

**输出 (晚调度):**  节点 `n` 的最晚调度位置可能是 `B0` (`B2` 和 `B3` 的公共支配节点，如果可以安全地提升)。如果不能提升，则可能是 `B1`。

**用户常见的编程错误 (间接相关)：**

虽然这段代码不直接涉及用户的编程错误，但其优化的目标是提高性能。用户编写低效的 JavaScript 代码，例如在循环内部进行不必要的计算，会使得调度器的优化更加重要。

**总结：**

这部分 `v8/src/compiler/scheduler.cc` 的代码主要负责为后续的代码生成阶段准备优化的基本块顺序和节点放置方案。它通过计算特殊的 RPO、循环信息和支配树来理解代码的结构，然后利用早调度和晚调度算法来确定每个节点的最佳执行位置，以提高代码的执行效率。它是 V8 编译器中至关重要的一个环节。

Prompt: 
```
这是目录为v8/src/compiler/scheduler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/scheduler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
ack_depth, succ, kBlockUnvisited2);
            if (HasLoopNumber(succ)) {
              // Push the inner loop onto the loop stack.
              DCHECK(GetLoopNumber(succ) < num_loops);
              LoopInfo* next = &loops_[GetLoopNumber(succ)];
              next->end = order;
              next->prev = loop;
              loop = next;
            }
          }
        } else {
          // Finished with all successors of the current block.
          if (HasLoopNumber(block)) {
            // If we are going to pop a loop header, then add its entire body.
            LoopInfo* info = &loops_[GetLoopNumber(block)];
            for (BasicBlock* b = info->start; true; b = b->rpo_next()) {
              if (b->rpo_next() == info->end) {
                b->set_rpo_next(order);
                info->end = order;
                break;
              }
            }
            order = info->start;
          } else {
            // Pop a single node off the stack and add it to the order.
            order = PushFront(order, block);
            block->set_rpo_number(kBlockVisited2);
          }
          stack_depth--;
        }
      }
    }

    // Publish new order the first time.
    if (order_ == nullptr) order_ = order;

    // Compute the correct loop headers and set the correct loop ends.
    LoopInfo* current_loop = nullptr;
    BasicBlock* current_header = entry->loop_header();
    int32_t loop_depth = entry->loop_depth();
    if (entry->IsLoopHeader()) --loop_depth;  // Entry might be a loop header.
    for (BasicBlock* b = order; b != insertion_point; b = b->rpo_next()) {
      BasicBlock* current = b;

      // Reset BasicBlock::rpo_number again.
      current->set_rpo_number(kBlockUnvisited1);

      // Finish the previous loop(s) if we just exited them.
      while (current_header != nullptr &&
             current == current_header->loop_end()) {
        DCHECK(current_header->IsLoopHeader());
        DCHECK_NOT_NULL(current_loop);
        current_loop = current_loop->prev;
        current_header =
            current_loop == nullptr ? nullptr : current_loop->header;
        --loop_depth;
      }
      current->set_loop_header(current_header);

      // Push a new loop onto the stack if this loop is a loop header.
      if (HasLoopNumber(current)) {
        ++loop_depth;
        current_loop = &loops_[GetLoopNumber(current)];
        BasicBlock* loop_end = current_loop->end;
        current->set_loop_end(loop_end == nullptr ? BeyondEndSentinel()
                                                  : loop_end);
        current_header = current_loop->header;
        TRACE("id:%d is a loop header, increment loop depth to %d\n",
              current->id().ToInt(), loop_depth);
      }

      current->set_loop_depth(loop_depth);

      if (current->loop_header() == nullptr) {
        TRACE("id:%d is not in a loop (depth == %d)\n", current->id().ToInt(),
              current->loop_depth());
      } else {
        TRACE("id:%d has loop header id:%d, (depth == %d)\n",
              current->id().ToInt(), current->loop_header()->id().ToInt(),
              current->loop_depth());
      }
    }
  }

  // Computes loop membership from the backedges of the control flow graph.
  void ComputeLoopInfo(ZoneVector<SpecialRPOStackFrame>* queue,
                       size_t num_loops, ZoneVector<Backedge>* backedges) {
    // Extend existing loop membership vectors.
    for (LoopInfo& loop : loops_) {
      loop.members->Resize(static_cast<int>(schedule_->BasicBlockCount()),
                           zone_);
    }

    // Extend loop information vector.
    loops_.resize(num_loops, LoopInfo());

    // Compute loop membership starting from backedges.
    // O(max(loop_depth) * max(|loop|)
    for (size_t i = 0; i < backedges->size(); i++) {
      BasicBlock* member = backedges->at(i).first;
      BasicBlock* header = member->SuccessorAt(backedges->at(i).second);
      size_t loop_num = GetLoopNumber(header);
      if (loops_[loop_num].header == nullptr) {
        loops_[loop_num].header = header;
        loops_[loop_num].members = zone_->New<BitVector>(
            static_cast<int>(schedule_->BasicBlockCount()), zone_);
      }

      int queue_length = 0;
      if (member != header) {
        // As long as the header doesn't have a backedge to itself,
        // Push the member onto the queue and process its predecessors.
        if (!loops_[loop_num].members->Contains(member->id().ToInt())) {
          loops_[loop_num].members->Add(member->id().ToInt());
        }
        (*queue)[queue_length++].block = member;
      }

      // Propagate loop membership backwards. All predecessors of M up to the
      // loop header H are members of the loop too. O(|blocks between M and H|).
      while (queue_length > 0) {
        BasicBlock* block = (*queue)[--queue_length].block;
        for (size_t j = 0; j < block->PredecessorCount(); j++) {
          BasicBlock* pred = block->PredecessorAt(j);
          if (pred != header) {
            if (!loops_[loop_num].members->Contains(pred->id().ToInt())) {
              loops_[loop_num].members->Add(pred->id().ToInt());
              (*queue)[queue_length++].block = pred;
            }
          }
        }
      }
    }
  }

#if DEBUG
  void PrintRPO() {
    StdoutStream os;
    os << "RPO with " << loops_.size() << " loops";
    if (loops_.size() > 0) {
      os << " (";
      for (size_t i = 0; i < loops_.size(); i++) {
        if (i > 0) os << " ";
        os << "id:" << loops_[i].header->id();
      }
      os << ")";
    }
    os << ":\n";

    for (BasicBlock* block = order_; block != nullptr;
         block = block->rpo_next()) {
      os << std::setw(5) << "B" << block->rpo_number() << ":";
      for (size_t i = 0; i < loops_.size(); i++) {
        bool range = loops_[i].header->LoopContains(block);
        bool membership = loops_[i].header != block && range;
        os << (membership ? " |" : "  ");
        os << (range ? "x" : " ");
      }
      os << "  id:" << block->id() << ": ";
      if (block->loop_end() != nullptr) {
        os << " range: [B" << block->rpo_number() << ", B"
           << block->loop_end()->rpo_number() << ")";
      }
      if (block->loop_header() != nullptr) {
        os << " header: id:" << block->loop_header()->id();
      }
      if (block->loop_depth() > 0) {
        os << " depth: " << block->loop_depth();
      }
      os << "\n";
    }
  }

  void VerifySpecialRPO() {
    BasicBlockVector* order = schedule_->rpo_order();
    DCHECK_LT(0, order->size());
    DCHECK_EQ(0, (*order)[0]->id().ToInt());  // entry should be first.

    for (size_t i = 0; i < loops_.size(); i++) {
      LoopInfo* loop = &loops_[i];
      BasicBlock* header = loop->header;
      BasicBlock* end = header->loop_end();

      DCHECK_NOT_NULL(header);
      DCHECK_LE(0, header->rpo_number());
      DCHECK_LT(header->rpo_number(), order->size());
      DCHECK_NOT_NULL(end);
      DCHECK_LE(end->rpo_number(), order->size());
      DCHECK_GT(end->rpo_number(), header->rpo_number());
      DCHECK_NE(header->loop_header(), header);

      // Verify the start ... end list relationship.
      int links = 0;
      BasicBlock* block = loop->start;
      DCHECK_EQ(header, block);
      bool end_found;
      while (true) {
        if (block == nullptr || block == loop->end) {
          end_found = (loop->end == block);
          break;
        }
        // The list should be in same order as the final result.
        DCHECK(block->rpo_number() == links + header->rpo_number());
        links++;
        block = block->rpo_next();
        DCHECK_LT(links, static_cast<int>(2 * order->size()));  // cycle?
      }
      DCHECK_LT(0, links);
      DCHECK_EQ(links, end->rpo_number() - header->rpo_number());
      DCHECK(end_found);

      // Check loop depth of the header.
      int loop_depth = 0;
      for (LoopInfo* outer = loop; outer != nullptr; outer = outer->prev) {
        loop_depth++;
      }
      DCHECK_EQ(loop_depth, header->loop_depth());

      // Check the contiguousness of loops.
      int count = 0;
      for (int j = 0; j < static_cast<int>(order->size()); j++) {
        block = order->at(j);
        DCHECK_EQ(block->rpo_number(), j);
        if (j < header->rpo_number() || j >= end->rpo_number()) {
          DCHECK(!header->LoopContains(block));
        } else {
          DCHECK(header->LoopContains(block));
          DCHECK_GE(block->loop_depth(), loop_depth);
          count++;
        }
      }
      DCHECK_EQ(links, count);
    }
  }
#endif  // DEBUG

  Zone* zone_;
  Schedule* schedule_;
  BasicBlock* order_;
  BasicBlock* beyond_end_;
  ZoneVector<LoopInfo> loops_;
  ZoneVector<Backedge> backedges_;
  ZoneVector<SpecialRPOStackFrame> stack_;
  size_t previous_block_count_;
  ZoneVector<BasicBlock*> const empty_;
};


BasicBlockVector* Scheduler::ComputeSpecialRPO(Zone* zone, Schedule* schedule) {
  SpecialRPONumberer numberer(zone, schedule);
  numberer.ComputeSpecialRPO();
  numberer.SerializeRPOIntoSchedule();
  numberer.PrintAndVerifySpecialRPO();
  return schedule->rpo_order();
}


void Scheduler::ComputeSpecialRPONumbering() {
  TRACE("--- COMPUTING SPECIAL RPO ----------------------------------\n");

  // Compute the special reverse-post-order for basic blocks.
  special_rpo_ = zone_->New<SpecialRPONumberer>(zone_, schedule_);
  special_rpo_->ComputeSpecialRPO();
}

BasicBlock* Scheduler::GetCommonDominatorIfCached(BasicBlock* b1,
                                                  BasicBlock* b2) {
  auto entry1 = common_dominator_cache_.find(b1->id().ToInt());
  if (entry1 == common_dominator_cache_.end()) return nullptr;
  auto entry2 = entry1->second->find(b2->id().ToInt());
  if (entry2 == entry1->second->end()) return nullptr;
  return entry2->second;
}

BasicBlock* Scheduler::GetCommonDominator(BasicBlock* b1, BasicBlock* b2) {
  // A very common fast case:
  if (b1 == b2) return b1;
  // Try to find the common dominator by walking, if there is a chance of
  // finding it quickly.
  constexpr int kCacheGranularity = 63;
  static_assert((kCacheGranularity & (kCacheGranularity + 1)) == 0);
  int depth_difference = b1->dominator_depth() - b2->dominator_depth();
  if (depth_difference > -kCacheGranularity &&
      depth_difference < kCacheGranularity) {
    for (int i = 0; i < kCacheGranularity; i++) {
      if (b1->dominator_depth() < b2->dominator_depth()) {
        b2 = b2->dominator();
      } else {
        b1 = b1->dominator();
      }
      if (b1 == b2) return b1;
    }
    // We might fall out of the loop here if the dominator tree has several
    // deep "parallel" subtrees.
  }
  // If it'd be a long walk, take the bus instead (i.e. use the cache).
  // To keep memory consumption low, there'll be a bus stop every 64 blocks.
  // First, walk to the nearest bus stop.
  if (b1->dominator_depth() < b2->dominator_depth()) std::swap(b1, b2);
  while ((b1->dominator_depth() & kCacheGranularity) != 0) {
    if (V8_LIKELY(b1->dominator_depth() > b2->dominator_depth())) {
      b1 = b1->dominator();
    } else {
      b2 = b2->dominator();
    }
    if (b1 == b2) return b1;
  }
  // Then, walk from bus stop to bus stop until we either find a bus (i.e. an
  // existing cache entry) or the result. Make a list of any empty bus stops
  // we'd like to populate for next time.
  constexpr int kMaxNewCacheEntries = 2 * 50;  // Must be even.
  // This array stores a flattened list of pairs, e.g. if after finding the
  // {result}, we want to cache [(B11, B12) -> result, (B21, B22) -> result],
  // then we store [11, 12, 21, 22] here.
  int new_cache_entries[kMaxNewCacheEntries];
  // Next free slot in {new_cache_entries}.
  int new_cache_entries_cursor = 0;
  while (b1 != b2) {
    if ((b1->dominator_depth() & kCacheGranularity) == 0) {
      BasicBlock* maybe_cache_hit = GetCommonDominatorIfCached(b1, b2);
      if (maybe_cache_hit != nullptr) {
        b1 = b2 = maybe_cache_hit;
        break;
      } else if (new_cache_entries_cursor < kMaxNewCacheEntries) {
        new_cache_entries[new_cache_entries_cursor++] = b1->id().ToInt();
        new_cache_entries[new_cache_entries_cursor++] = b2->id().ToInt();
      }
    }
    if (V8_LIKELY(b1->dominator_depth() > b2->dominator_depth())) {
      b1 = b1->dominator();
    } else {
      b2 = b2->dominator();
    }
  }
  // Lastly, create new cache entries we noted down earlier.
  BasicBlock* result = b1;
  for (int i = 0; i < new_cache_entries_cursor;) {
    int id1 = new_cache_entries[i++];
    int id2 = new_cache_entries[i++];
    ZoneMap<int, BasicBlock*>* mapping;
    auto entry = common_dominator_cache_.find(id1);
    if (entry == common_dominator_cache_.end()) {
      mapping = zone_->New<ZoneMap<int, BasicBlock*>>(zone_);
      common_dominator_cache_[id1] = mapping;
    } else {
      mapping = entry->second;
    }
    // If there was an existing entry, we would have found it earlier.
    DCHECK_EQ(mapping->find(id2), mapping->end());
    mapping->insert({id2, result});
  }
  return result;
}

void Scheduler::PropagateImmediateDominators(BasicBlock* block) {
  for (/*nop*/; block != nullptr; block = block->rpo_next()) {
    auto pred = block->predecessors().begin();
    auto end = block->predecessors().end();
    DCHECK(pred != end);  // All blocks except start have predecessors.
    BasicBlock* dominator = *pred;
    bool deferred = dominator->deferred();
    // For multiple predecessors, walk up the dominator tree until a common
    // dominator is found. Visitation order guarantees that all predecessors
    // except for backwards edges have been visited.
    // We use a one-element cache for previously-seen dominators. This gets
    // hit a lot for functions that have long chains of diamonds, and in
    // those cases turns quadratic into linear complexity.
    BasicBlock* cache = nullptr;
    for (++pred; pred != end; ++pred) {
      // Don't examine backwards edges.
      if ((*pred)->dominator_depth() < 0) continue;
      if ((*pred)->dominator_depth() > 3 &&
          ((*pred)->dominator()->dominator() == cache ||
           (*pred)->dominator()->dominator()->dominator() == cache)) {
        // Nothing to do, the last iteration covered this case.
        DCHECK_EQ(dominator, BasicBlock::GetCommonDominator(dominator, *pred));
      } else {
        dominator = BasicBlock::GetCommonDominator(dominator, *pred);
      }
      cache = (*pred)->dominator();
      deferred = deferred & (*pred)->deferred();
    }
    block->set_dominator(dominator);
    block->set_dominator_depth(dominator->dominator_depth() + 1);
    block->set_deferred(deferred | block->deferred());
    TRACE("Block id:%d's idom is id:%d, depth = %d\n", block->id().ToInt(),
          dominator->id().ToInt(), block->dominator_depth());
  }
}

void Scheduler::GenerateDominatorTree(Schedule* schedule) {
  // Seed start block to be the first dominator.
  schedule->start()->set_dominator_depth(0);

  // Build the block dominator tree resulting from the above seed.
  PropagateImmediateDominators(schedule->start()->rpo_next());
}

void Scheduler::GenerateDominatorTree() {
  TRACE("--- IMMEDIATE BLOCK DOMINATORS -----------------------------\n");
  GenerateDominatorTree(schedule_);
}

// -----------------------------------------------------------------------------
// Phase 3: Prepare use counts for nodes.


class PrepareUsesVisitor {
 public:
  explicit PrepareUsesVisitor(Scheduler* scheduler, Graph* graph, Zone* zone)
      : scheduler_(scheduler),
        schedule_(scheduler->schedule_),
        graph_(graph),
        visited_(static_cast<int>(graph_->NodeCount()), zone),
        stack_(zone) {}

  void Run() {
    InitializePlacement(graph_->end());
    while (!stack_.empty()) {
      Node* node = stack_.top();
      stack_.pop();
      VisitInputs(node);
    }
  }

 private:
  void InitializePlacement(Node* node) {
    TRACE("Pre #%d:%s\n", node->id(), node->op()->mnemonic());
    DCHECK(!Visited(node));
    if (scheduler_->InitializePlacement(node) == Scheduler::kFixed) {
      // Fixed nodes are always roots for schedule late.
      scheduler_->schedule_root_nodes_.push_back(node);
      if (!schedule_->IsScheduled(node)) {
        // Make sure root nodes are scheduled in their respective blocks.
        TRACE("Scheduling fixed position node #%d:%s\n", node->id(),
              node->op()->mnemonic());
        IrOpcode::Value opcode = node->opcode();
        BasicBlock* block =
            opcode == IrOpcode::kParameter
                ? schedule_->start()
                : schedule_->block(NodeProperties::GetControlInput(node));
        DCHECK_NOT_NULL(block);
        schedule_->AddNode(block, node);
      }
    }
    stack_.push(node);
    visited_.Add(node->id());
  }

  void VisitInputs(Node* node) {
    DCHECK_NE(scheduler_->GetPlacement(node), Scheduler::kUnknown);
    bool is_scheduled = schedule_->IsScheduled(node);
    std::optional<int> coupled_control_edge =
        scheduler_->GetCoupledControlEdge(node);
    for (auto edge : node->input_edges()) {
      Node* to = edge.to();
      DCHECK_EQ(node, edge.from());
      if (!Visited(to)) {
        InitializePlacement(to);
      }
      TRACE("PostEdge #%d:%s->#%d:%s\n", node->id(), node->op()->mnemonic(),
            to->id(), to->op()->mnemonic());
      DCHECK_NE(scheduler_->GetPlacement(to), Scheduler::kUnknown);
      if (!is_scheduled && edge.index() != coupled_control_edge) {
        scheduler_->IncrementUnscheduledUseCount(to, node);
      }
    }
  }

  bool Visited(Node* node) { return visited_.Contains(node->id()); }

  Scheduler* scheduler_;
  Schedule* schedule_;
  Graph* graph_;
  BitVector visited_;
  ZoneStack<Node*> stack_;
};


void Scheduler::PrepareUses() {
  TRACE("--- PREPARE USES -------------------------------------------\n");

  // Count the uses of every node, which is used to ensure that all of a
  // node's uses are scheduled before the node itself.
  PrepareUsesVisitor prepare_uses(this, graph_, zone_);
  prepare_uses.Run();
}


// -----------------------------------------------------------------------------
// Phase 4: Schedule nodes early.


class ScheduleEarlyNodeVisitor {
 public:
  ScheduleEarlyNodeVisitor(Zone* zone, Scheduler* scheduler)
      : scheduler_(scheduler), schedule_(scheduler->schedule_), queue_(zone) {}

  // Run the schedule early algorithm on a set of fixed root nodes.
  void Run(NodeVector* roots) {
    for (Node* const root : *roots) {
      queue_.push(root);
    }

    while (!queue_.empty()) {
      scheduler_->tick_counter_->TickAndMaybeEnterSafepoint();
      VisitNode(queue_.front());
      queue_.pop();
    }
  }

 private:
  // Visits one node from the queue and propagates its current schedule early
  // position to all uses. This in turn might push more nodes onto the queue.
  void VisitNode(Node* node) {
    Scheduler::SchedulerData* data = scheduler_->GetData(node);

    // Fixed nodes already know their schedule early position.
    if (scheduler_->GetPlacement(node) == Scheduler::kFixed) {
      data->minimum_block_ = schedule_->block(node);
      TRACE("Fixing #%d:%s minimum_block = id:%d, dominator_depth = %d\n",
            node->id(), node->op()->mnemonic(),
            data->minimum_block_->id().ToInt(),
            data->minimum_block_->dominator_depth());
    }

    // No need to propagate unconstrained schedule early positions.
    if (data->minimum_block_ == schedule_->start()) return;

    // Propagate schedule early position.
    DCHECK_NOT_NULL(data->minimum_block_);
    for (auto use : node->uses()) {
      if (scheduler_->IsLive(use)) {
        PropagateMinimumPositionToNode(data->minimum_block_, use);
      }
    }
  }

  // Propagates {block} as another minimum position into the given {node}. This
  // has the net effect of computing the minimum dominator block of {node} that
  // still post-dominates all inputs to {node} when the queue is processed.
  void PropagateMinimumPositionToNode(BasicBlock* block, Node* node) {
    Scheduler::SchedulerData* data = scheduler_->GetData(node);

    // No need to propagate to fixed node, it's guaranteed to be a root.
    if (scheduler_->GetPlacement(node) == Scheduler::kFixed) return;

    // Coupled nodes influence schedule early position of their control.
    if (scheduler_->GetPlacement(node) == Scheduler::kCoupled) {
      Node* control = NodeProperties::GetControlInput(node);
      PropagateMinimumPositionToNode(block, control);
    }

    // Propagate new position if it is deeper down the dominator tree than the
    // current. Note that all inputs need to have minimum block position inside
    // the dominator chain of {node}'s minimum block position.
    DCHECK(InsideSameDominatorChain(block, data->minimum_block_));
    if (block->dominator_depth() > data->minimum_block_->dominator_depth()) {
      data->minimum_block_ = block;
      queue_.push(node);
      TRACE("Propagating #%d:%s minimum_block = id:%d, dominator_depth = %d\n",
            node->id(), node->op()->mnemonic(),
            data->minimum_block_->id().ToInt(),
            data->minimum_block_->dominator_depth());
    }
  }

#if DEBUG
  bool InsideSameDominatorChain(BasicBlock* b1, BasicBlock* b2) {
    BasicBlock* dominator = BasicBlock::GetCommonDominator(b1, b2);
    return dominator == b1 || dominator == b2;
  }
#endif

  Scheduler* scheduler_;
  Schedule* schedule_;
  ZoneQueue<Node*> queue_;
};


void Scheduler::ScheduleEarly() {
  if (!special_rpo_->HasLoopBlocks()) {
    TRACE("--- NO LOOPS SO SKIPPING SCHEDULE EARLY --------------------\n");
    return;
  }

  TRACE("--- SCHEDULE EARLY -----------------------------------------\n");
  if (v8_flags.trace_turbo_scheduler) {
    TRACE("roots: ");
    for (Node* node : schedule_root_nodes_) {
      TRACE("#%d:%s ", node->id(), node->op()->mnemonic());
    }
    TRACE("\n");
  }

  // Compute the minimum block for each node thereby determining the earliest
  // position each node could be placed within a valid schedule.
  ScheduleEarlyNodeVisitor schedule_early_visitor(zone_, this);
  schedule_early_visitor.Run(&schedule_root_nodes_);
}


// -----------------------------------------------------------------------------
// Phase 5: Schedule nodes late.


class ScheduleLateNodeVisitor {
 public:
  ScheduleLateNodeVisitor(Zone* zone, Scheduler* scheduler)
      : zone_(zone),
        scheduler_(scheduler),
        schedule_(scheduler_->schedule_),
        marking_queue_(scheduler->zone_) {}

  // Run the schedule late algorithm on a set of fixed root nodes.
  void Run(NodeVector* roots) {
    for (Node* const root : *roots) {
      ProcessQueue(root);
    }
  }

 private:
  void ProcessQueue(Node* root) {
    ZoneQueue<Node*>* queue = &(scheduler_->schedule_queue_);
    for (Node* node : root->inputs()) {
      // Don't schedule coupled nodes on their own.
      if (scheduler_->GetPlacement(node) == Scheduler::kCoupled) {
        node = NodeProperties::GetControlInput(node);
      }

      // Test schedulability condition by looking at unscheduled use count.
      if (scheduler_->GetData(node)->unscheduled_count_ != 0) continue;

      queue->push(node);
      do {
        scheduler_->tick_counter_->TickAndMaybeEnterSafepoint();
        Node* const n = queue->front();
        queue->pop();
        VisitNode(n);
      } while (!queue->empty());
    }
  }

  // Visits one node from the queue of schedulable nodes and determines its
  // schedule late position. Also hoists nodes out of loops to find a more
  // optimal scheduling position.
  void VisitNode(Node* node) {
    DCHECK_EQ(0, scheduler_->GetData(node)->unscheduled_count_);

    // Don't schedule nodes that are already scheduled.
    if (schedule_->IsScheduled(node)) return;
    DCHECK_EQ(Scheduler::kSchedulable, scheduler_->GetPlacement(node));

    // Determine the dominating block for all of the uses of this node. It is
    // the latest block that this node can be scheduled in.
    TRACE("Scheduling #%d:%s\n", node->id(), node->op()->mnemonic());
    BasicBlock* block = GetCommonDominatorOfUses(node);
    DCHECK_NOT_NULL(block);

    // The schedule early block dominates the schedule late block.
    BasicBlock* min_block = scheduler_->GetData(node)->minimum_block_;
    DCHECK_EQ(min_block, BasicBlock::GetCommonDominator(block, min_block));

    TRACE(
        "Schedule late of #%d:%s is id:%d at loop depth %d, minimum = id:%d\n",
        node->id(), node->op()->mnemonic(), block->id().ToInt(),
        block->loop_depth(), min_block->id().ToInt());

    // Hoist nodes out of loops if possible. Nodes can be hoisted iteratively
    // into enclosing loop pre-headers until they would precede their schedule
    // early position.
    BasicBlock* hoist_block = GetHoistBlock(block);
    if (hoist_block &&
        hoist_block->dominator_depth() >= min_block->dominator_depth()) {
      DCHECK(scheduler_->special_rpo_->HasLoopBlocks());
      do {
        TRACE("  hoisting #%d:%s to block id:%d\n", node->id(),
              node->op()->mnemonic(), hoist_block->id().ToInt());
        DCHECK_LT(hoist_block->loop_depth(), block->loop_depth());
        block = hoist_block;
        hoist_block = GetHoistBlock(hoist_block);
      } while (hoist_block &&
               hoist_block->dominator_depth() >= min_block->dominator_depth());
    } else if (scheduler_->flags_ & Scheduler::kSplitNodes) {
      // Split the {node} if beneficial and return the new {block} for it.
      block = SplitNode(block, node);
    }

    // Schedule the node or a floating control structure.
    if (IrOpcode::IsMergeOpcode(node->opcode())) {
      ScheduleFloatingControl(block, node);
    } else if (node->opcode() == IrOpcode::kFinishRegion) {
      ScheduleRegion(block, node);
    } else {
      ScheduleNode(block, node);
    }
  }

  bool IsMarked(BasicBlock* block) const {
    return marked_.Contains(block->id().ToInt());
  }

  void Mark(BasicBlock* block) { marked_.Add(block->id().ToInt()); }

  // Mark {block} and push its non-marked predecessor on the marking queue.
  void MarkBlock(BasicBlock* block) {
    Mark(block);
    for (BasicBlock* pred_block : block->predecessors()) {
      if (IsMarked(pred_block)) continue;
      marking_queue_.push_back(pred_block);
    }
  }

  BasicBlock* SplitNode(BasicBlock* block, Node* node) {
    // For now, we limit splitting to pure nodes.
    if (!node->op()->HasProperty(Operator::kPure)) return block;
    // TODO(titzer): fix the special case of splitting of projections.
    if (node->opcode() == IrOpcode::kProjection) return block;

    // The {block} is common dominator of all uses of {node}, so we cannot
    // split anything unless the {block} has at least two successors.
    DCHECK_EQ(block, GetCommonDominatorOfUses(node));
    if (block->SuccessorCount() < 2) return block;

    // Clear marking bits.
    DCHECK(marking_queue_.empty());
    marked_.Clear();
    int new_size = static_cast<int>(schedule_->BasicBlockCount() + 1);
    if (marked_.length() < new_size) {
      marked_.Resize(new_size, scheduler_->zone_);
    }

    // Check if the {node} has uses in {block}.
    for (Edge edge : node->use_edges()) {
      if (!scheduler_->IsLive(edge.from())) continue;
      BasicBlock* use_block = GetBlockForUse(edge);
      if (use_block == nullptr || IsMarked(use_block)) continue;
      if (use_block == block) {
        TRACE("  not splitting #%d:%s, it is used in id:%d\n", node->id(),
              node->op()->mnemonic(), block->id().ToInt());
        marking_queue_.clear();
        return block;
      }
      MarkBlock(use_block);
    }

    // Compute transitive marking closure; a block is marked if all its
    // successors are marked.
    do {
      BasicBlock* top_block = marking_queue_.front();
      marking_queue_.pop_front();
      if (IsMarked(top_block)) continue;
      bool marked = true;
      if (top_block->loop_depth() == block->loop_depth()) {
        for (BasicBlock* successor : top_block->successors()) {
          if (!IsMarked(successor)) {
            marked = false;
            break;
          }
        }
      }
      if (marked) MarkBlock(top_block);
    } while (!marking_queue_.empty());

    // If the (common dominator) {block} is marked, we know that all paths from
    // {block} to the end contain at least one use of {node}, and hence there's
    // no point in splitting the {node} in this case.
    if (IsMarked(block)) {
      TRACE("  not splitting #%d:%s, its common dominator id:%d is perfect\n",
            node->id(), node->op()->mnemonic(), block->id().ToInt());
      return block;
    }

    // Split {node} for uses according to the previously computed marking
    // closure. Every marking partition has a unique dominator, which get's a
    // copy of the {node} with the exception of the first partition, which get's
    // the {node} itself.
    ZoneMap<BasicBlock*, Node*> dominators(scheduler_->zone_);
    for (Edge edge : node->use_edges()) {
      if (!scheduler_->IsLive(edge.from())) continue;
      BasicBlock* use_block = GetBlockForUse(edge);
      if (use_block == nullptr) continue;
      while (IsMarked(use_block->dominator())) {
        use_block = use_block->dominator();
      }
      auto& use_node = dominators[use_block];
      if (use_node == nullptr) {
        if (dominators.size() == 1u) {
          // Place the {node} at {use_block}.
          block = use_block;
          use_node = node;
          TRACE("  pushing #%d:%s down to id:%d\n", node->id(),
                node->op()->mnemonic(), block->id().ToInt());
        } else {
          // Place a copy of {node} at {use_block}.
          use_node = CloneNode(node);
          TRACE("  cloning #%d:%s for id:%d\n", use_node->id(),
                use_node->op()->mnemonic(), use_block->id().ToInt());
          scheduler_->schedule_queue_.push(use_node);
        }
      }
      edge.UpdateTo(use_node);
    }
    return block;
  }

  BasicBlock* GetHoistBlock(BasicBlock* block) {
    if (!scheduler_->special_rpo_->HasLoopBlocks()) return nullptr;
    if (block->IsLoopHeader()) return block->dominator();
    // We have to check to make sure that the {block} dominates all
    // of the outgoing blocks.  If it doesn't, then there is a path
    // out of the loop which does not execute this {block}, so we
    // can't hoist operations from this {block} out of the loop, as
    // that would introduce additional computations.
    if (BasicBlock* header_block = block->loop_header()) {
      for (BasicBlock* outgoing_block :
           scheduler_->special_rpo_->GetOutgoingBlocks(header_block)) {
        if (scheduler_->GetCommonDominator(block, outgoing_block) != block) {
          return nullptr;
        }
      }
      return header_block->dominator();
    }
    return nullptr;
  }

  BasicBlock* GetCommonDominatorOfUses(Node* node) {
    BasicBlock* block = nullptr;
    for (Edge edge : node->use_edges()) {
      if (!scheduler_->IsLive(edge.from())) continue;
      BasicBlock* use_block = GetBlockForUse(edge);
      block = block == nullptr
                  ? use_block
                  : use_block == nullptr
                        ? block
                        : scheduler_->GetCommonDominator(block, use_block);
    }
    return block;
  }

  BasicBlock* FindPredecessorBlock(Node* node) {
    return scheduler_->control_flow_builder_->FindPredecessorBlock(node);
  }

  BasicBlock* GetBlockForUse(Edge edge) {
    // TODO(titzer): ignore uses from dead nodes (not visited in PrepareUses()).
    // Dead uses only occur if the graph is not trimmed before scheduling.
    Node* use = edge.from();
    if (IrOpcode::IsPhiOpcode(use->opcode())) {
      // If the use is from a coupled (i.e. floating) phi, compute the common
      // dominator of its uses. This will not recurse more than one level.
      if (scheduler_->GetPlacement(use) == Scheduler::kCoupled) {
        TRACE("  inspecting uses of coupled #%d:%s\n", use->id(),
              use->op()->mnemonic());
        // TODO(titzer): reenable once above TODO is addressed.
        //        DCHECK_EQ(edge.to(), NodeProperties::GetControlInput(use));
        return GetCommonDominatorOfUses(use);
      }
      // If the use is from a fixed (i.e. non-floating) phi, we use the
      // predecessor block of the corresponding control input to the merge.
      if (scheduler_->GetPlacement(use) == Scheduler::kFixed) {
        TRACE("  input@%d into a fixed phi #%d:%s\n", edge.index(), use->id(),
              use->op()->mnemonic());
        Node* merge = NodeProperties::GetControlInput(use, 0);
        DCHECK(IrOpcode::IsMergeOpcode(merge->opcode()));
        Node* input = NodeProperties::GetControlInput(merge, edge.index());
        return FindPredecessorBlock(
"""


```