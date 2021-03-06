package io.mangoo.admin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.quartz.JobKey;
import org.quartz.SchedulerException;
import org.quartz.Trigger;
import org.quartz.Trigger.TriggerState;
import org.quartz.impl.matchers.GroupMatcher;

import io.mangoo.annotations.FilterWith;
import io.mangoo.cache.Cache;
import io.mangoo.core.Application;
import io.mangoo.enums.Default;
import io.mangoo.enums.Key;
import io.mangoo.enums.Template;
import io.mangoo.models.Job;
import io.mangoo.models.Metrics;
import io.mangoo.routing.Response;
import io.mangoo.routing.Router;
import io.mangoo.scheduler.Scheduler;

/**
 * Controller class for administrative URLs
 *
 * @author svenkubiak
 *
 */
@FilterWith(AdminFilter.class)
public class AdminController {
    private static final int MB = 1024*1024;
    private final Map<String, String> properties = new HashMap<>();
    
    public AdminController() {
        System.getProperties().entrySet().forEach(
                entry -> this.properties.put(entry.getKey().toString(), entry.getValue().toString())
        );
    }
    
    public Response health() {
        return Response.withOk()
                .andTextBody("alive");
    }

    public Response routes() {
        return Response.withOk()
                .andContent("routes", Router.getRoutes())
                .andTemplate(Template.DEFAULT.routesPath());
    }

    public Response cache() {
        Map<String, Object> stats = Application.getInstance(Cache.class).getStats();

        return Response.withOk()
                .andContent("stats", stats)
                .andTemplate(Template.DEFAULT.cachePath());
    }

    public Response config() {
        Map<String, String> configurations = Application.getConfig().getAllConfigurations();
        configurations.remove(Key.APPLICATION_SECRET.toString());

        return Response.withOk()
                .andContent("configuration", configurations)
                .andTemplate(Template.DEFAULT.configPath());
    }

    public Response metrics() {
        Metrics metrics = Application.getInstance(Metrics.class);

        return Response.withOk()
                .andContent("metrics", metrics.getMetrics())
                .andTemplate(Template.DEFAULT.metricsPath());
    }
    
    public Response system() {
        return Response.withOk()
                .andContent("properties", this.properties)
                .andTemplate(Template.DEFAULT.propertiesPath());
    }
    
    public Response memory() {
        Runtime runtime = Runtime.getRuntime();
        double usedMemory = (runtime.totalMemory() - runtime.freeMemory()) / MB;
        double freeMemory = runtime.freeMemory() / MB;
        double totalMemory = runtime.totalMemory() / MB;
        double maxMemory = runtime.maxMemory() / MB;
        
        return Response.withOk()
                .andContent("usedMemory", usedMemory)
                .andContent("freeMemory", freeMemory)
                .andContent("totalMemory", totalMemory)
                .andContent("maxMemory", maxMemory)
                .andTemplate(Template.DEFAULT.memoryPath());
    }

    public Response scheduler() throws SchedulerException {
        List<Job> jobs = new ArrayList<>();
        org.quartz.Scheduler scheduler = Application.getInstance(Scheduler.class).getScheduler();
        if (scheduler != null) {
            Set<JobKey> jobKeys = scheduler.getJobKeys(GroupMatcher.jobGroupEquals(Default.SCHEDULER_JOB_GROUP.toString()));
            for (JobKey jobKey : jobKeys) {
                List<? extends Trigger> triggers = scheduler.getTriggersOfJob(jobKey);
                Trigger trigger = triggers.get(0);
                TriggerState triggerState = scheduler.getTriggerState(trigger.getKey());
                jobs.add(new Job(TriggerState.PAUSED.equals(triggerState) ? false : true, jobKey.getName(), trigger.getDescription(), trigger.getNextFireTime(), trigger.getPreviousFireTime()));
            }
        }

        return Response.withOk()
                .andContent("jobs", jobs)
                .andTemplate(Template.DEFAULT.schedulerPath());
    }
}