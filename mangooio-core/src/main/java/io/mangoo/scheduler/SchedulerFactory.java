package io.mangoo.scheduler;

import java.util.Objects;

import org.quartz.Job;
import org.quartz.Scheduler;
import org.quartz.spi.JobFactory;
import org.quartz.spi.TriggerFiredBundle;

import io.mangoo.core.Application;

/**
 * Factory method for passing Scheduler job instance to the Google Guice injector
 *
 * @author svenkubiak
 *
 */
public class SchedulerFactory implements JobFactory {
    @Override
    public Job newJob(final TriggerFiredBundle triggerFiredBundle, final Scheduler scheduler) {
        Objects.requireNonNull(triggerFiredBundle, "triggerFiredBundle is required for a new job");
        Objects.requireNonNull(scheduler, "scheduler is required for a new job");

        return Application.getInstance(triggerFiredBundle.getJobDetail().getJobClass());
    }
}