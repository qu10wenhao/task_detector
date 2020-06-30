Task Detector
------

Schedsnoop is a tool that traces the related schedule events of a specified task, e.g. the migration, sched in/out, wakeup and sleep/block. It will record the preemption information during tracing and output a report at the end to find out who has stolen the CPU for the most.

By execute command 'schedsnoop -t 4314', we continually trace the schedule events related to 'test' and finally output a report to show the top 10 processes that have preempted our target task (sorted by average preemption time):

```Shell
# schedsnoop -t 26371
Start tracing schedule events related to tid 26371
Press CTRL+C or wait until target exits to see report

Preemption Report:
CPU  TID    COMM                          Count  Avg       Longest   
2    2487   gsd-color                     1      139us     139us     
2    3241   gmain                         8      44us      92us      
2    0      swapper/2                     5      33us      38us      
2    1546   crond                         1      30us      30us      
2    697    kworker/2:1H                  11     13us      40us      
2    2798   JS Helper                     1      10us      10us      
2    24667  kworker/2:1                   8      8487ns    18us      
2    20     migration/2                   8      3475ns    4133ns    
2    1297   xfsaild/dm-2                  2      3149ns    3206ns    
```

It can also tracing the syscall by append options -s.

```Shell
# schedsnoop -t 26371 -s
Start tracing schedule events related to tid 26371(include SYSCALL)
Press CTRL+C or wait until target exits to see report

Preemption Report:
CPU  TID    COMM                          Count  Avg       Longest   
5    26371  test[35:nanosleep]            7      2043ms    2120ms    
5    0      swapper/5                     8      45us      97us      
5    694    kworker/5:1H                  8      37us      224us     
5    2      kthreadd                      1      28us      28us      
5    26371  test[1:write]                 15     25us      55us      
5    26248  kworker/5:5                   11     10us      30us      
5    35     migration/5                   10     2854ns    3836ns    
```

With log option -l, it will print each related events synchronously with human-readable format, which could be more helpful on debugging the competition on CPU resource.
Add debug option -d extraly could print raw timestamp.

```Shell
# schedsnoop -t 26371 -l
Start tracing schedule events related to tid 26371
Press CTRL+C or wait until target exits to see report
----------------------------
21:29:20.556477     CPU=5      TID=26371  COMM=test                ENQUEUE                                               
21:29:20.556509     CPU=5      TID=0      COMM=swapper/5           PREEMPTED                            32us             
21:29:20.556514     CPU=5      TID=26371  COMM=test                EXECUTE AFTER WAITED                 37us             
21:29:24.366207     CPU=5      TID=26371  COMM=test                WAIT AFTER EXECUTED                  3809ms           
21:29:24.366212     CPU=5      TID=35     COMM=migration/5         PREEMPT                                               
21:29:24.366223     CPU=5      TID=35     COMM=migration/5         DEQUEUE AFTER PREEMPTED              10us             
21:29:24.366241     CPU=5      TID=26371  COMM=test                EXECUTE AFTER WAITED                 34us             
21:29:25.736573     CPU=5      TID=26371  COMM=test                DEQUEUE AFTER EXECUTED               1370ms           
...
``` 
