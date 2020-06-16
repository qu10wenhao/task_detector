Task Detector
------

This is a tool to trace the related schedule events of a specified task, eg the migration, sched in/out, wakeup and sleep/block.

The event was translated into sentence to be more readable, by execute command 'task_detector -p 49870' we continually tracing the schedule events related to 'top' like:


Start tracing target task, pid 24104
----------------------------
102770938643193            CPU=1      PID=24104  COMM=top                 ENQUEUE                                               
102770938684071            CPU=1      PID=0      COMM=IDLE                PREEMPTED                            40us             
102770938684854            CPU=1      PID=24104  COMM=top                 EXECUTE AFTER WAITED                 41us             
102770949149591            CPU=1      PID=24104  COMM=top                 WAIT AFTER EXECUTED                  10464us          
102770949149957            CPU=1      PID=24190  COMM=kworker/1:5-mm_     PREEMPT                                               
102770949153368            CPU=1      PID=24190  COMM=kworker/1:5-mm_     DEQUEUE AFTER PREEMPTED              3411ns           
102770949153470            CPU=1      PID=24104  COMM=top                 EXECUTE AFTER WAITED                 3879ns           
102770949277377            CPU=1      PID=24104  COMM=top                 DEQUEUE AFTER EXECUTED               123us    
----------------------------

This could be helpful on debugging the competition on CPU resource, to find out who has stolen the CPU and how much it stolen.

It can also tracing the syscall by append options -s.
