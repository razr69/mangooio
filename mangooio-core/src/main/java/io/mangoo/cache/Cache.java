package io.mangoo.cache;

import java.util.Map;
import java.util.concurrent.ConcurrentMap;

/**
 * 
 * @author svenkubiak
 *
 */
public interface Cache {

    /**
     * Adds a value to cache with a given key overwriting and existing value
     *
     * @param key The key for the cached value
     * @param value The value to store
     */
    public void put(String key, Object value);

    /**
     * Removes a value with a given key from the cache
     *
     * @param key The key for the cached value
     */
    public void remove(String key);

    /**
     * Returns the size (number of elements) of cached values
     *
     * @return Cache size
     */
    public long size();

    /**
     * Clears the complete cache by invalidating all entries
     */
    public void clear();

    /**
     * Retrieves an object from the caches and converts it to
     * a given class
     *
     * @param key The key for the cached value
     * @param <T> JavaDoc requires this (just ignore it)
     *
     * @return A converted cache class value
     */
    public <T> T get(String key);

    /**
     * Adds a complete map of objects to the cache
     *
     * @param map The map to add
     */
    public void putAll(Map<String, Object> map);

    /**
     * @return The complete content of the cache
     */
    public ConcurrentMap<String, Object> getAll();

    /**
     * Retrieves the cache statistics
     *
     * @return Map containing cache statistics
     */
    public Map<String, Object> getStats();
}