import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from .node_manager import NodeManager, ScanNode

@dataclass
class ScanTask:
    task_id: str
    scanner_type: str
    target: str
    config: Dict[str, Any]
    priority: int = 1
    assigned_node: Optional[str] = None

class TaskDistributor:
    """Distributes scan tasks across available nodes"""
    
    def __init__(self, node_manager: NodeManager):
        self.node_manager = node_manager
        self.pending_tasks: List[ScanTask] = []
        self.active_tasks: Dict[str, ScanTask] = {}
        self.completed_tasks: Dict[str, Dict[str, Any]] = {}
    
    def submit_task(self, task: ScanTask) -> bool:
        """Submit a task for distributed execution"""
        self.pending_tasks.append(task)
        self.pending_tasks.sort(key=lambda t: t.priority, reverse=True)
        return True
    
    async def distribute_tasks(self) -> int:
        """Distribute pending tasks to available nodes"""
        distributed_count = 0
        
        while self.pending_tasks:
            task = self.pending_tasks[0]
            
            # Find available node with required capability
            available_nodes = self.node_manager.get_available_nodes(task.scanner_type)
            if not available_nodes:
                break
            
            # Assign task to first available node
            node = available_nodes[0]
            task.assigned_node = node.node_id
            
            # Update node status
            self.node_manager.update_node_status(node.node_id, "busy")
            
            # Move task from pending to active
            self.pending_tasks.pop(0)
            self.active_tasks[task.task_id] = task
            
            # Execute task (simplified - in real implementation would use network calls)
            asyncio.create_task(self._execute_task_on_node(task, node))
            distributed_count += 1
        
        return distributed_count
    
    async def _execute_task_on_node(self, task: ScanTask, node: ScanNode):
        """Execute task on remote node (simplified implementation)"""
        try:
            # Simulate task execution
            await asyncio.sleep(2)
            
            # Simulate results
            results = {
                'task_id': task.task_id,
                'status': 'completed',
                'results': {'simulated': True, 'node': node.node_id}
            }
            
            # Store results and cleanup
            self.completed_tasks[task.task_id] = results
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            
            # Update node status back to idle
            self.node_manager.update_node_status(node.node_id, "idle")
            
        except Exception:
            # Handle task failure
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            self.node_manager.update_node_status(node.node_id, "idle")
    
    def get_task_status(self, task_id: str) -> Optional[str]:
        """Get status of a specific task"""
        if task_id in self.completed_tasks:
            return "completed"
        elif task_id in self.active_tasks:
            return "running"
        elif any(t.task_id == task_id for t in self.pending_tasks):
            return "pending"
        return None
    
    def get_task_results(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get results for completed task"""
        return self.completed_tasks.get(task_id)