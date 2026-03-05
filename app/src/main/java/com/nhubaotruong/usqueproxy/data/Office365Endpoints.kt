package com.nhubaotruong.usqueproxy.data

import android.content.Context
import android.util.Log
import org.json.JSONArray
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches and caches Microsoft Office 365 IP ranges from the official endpoint API.
 * Returns CIDR blocks (both IPv4 and IPv6) that can be excluded from VPN routing.
 */
object Office365Endpoints {

    private const val TAG = "Office365Endpoints"
    private const val CACHE_FILE = "office365_ips.json"
    private const val CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000L // 1 day
    private const val ENDPOINT_URL =
        "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"

    /**
     * Returns cached O365 IP ranges, refreshing if stale. Suitable for calling from IO dispatcher.
     * Never throws — returns empty list on failure.
     */
    fun getIpRanges(context: Context): List<String> {
        val cacheFile = File(context.filesDir, CACHE_FILE)

        // If cache is fresh, return it directly
        if (cacheFile.exists() && System.currentTimeMillis() - cacheFile.lastModified() < CACHE_MAX_AGE_MS) {
            return readCache(cacheFile)
        }

        // Try to fetch fresh data
        val fetched = fetchFromApi()
        if (fetched.isNotEmpty()) {
            writeCache(cacheFile, fetched)
            return fetched
        }

        // Fall back to stale cache
        if (cacheFile.exists()) {
            Log.w(TAG, "Fetch failed, using stale cache")
            return readCache(cacheFile)
        }

        Log.w(TAG, "No cache available and fetch failed")
        return emptyList()
    }

    /**
     * Forces a refresh of the cache. Call on VPN start to keep data fresh.
     */
    fun refreshCache(context: Context) {
        val cacheFile = File(context.filesDir, CACHE_FILE)
        val fetched = fetchFromApi()
        if (fetched.isNotEmpty()) {
            writeCache(cacheFile, fetched)
        }
    }

    private fun fetchFromApi(): List<String> = try {
        val url = URL(ENDPOINT_URL)
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000
        conn.requestMethod = "GET"

        val responseCode = conn.responseCode
        if (responseCode == HttpURLConnection.HTTP_OK) {
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            parseIpRanges(body)
        } else {
            Log.w(TAG, "API returned HTTP $responseCode")
            emptyList()
        }
    } catch (e: Exception) {
        Log.w(TAG, "Failed to fetch O365 endpoints", e)
        emptyList()
    }

    private fun parseIpRanges(json: String): List<String> {
        val result = mutableSetOf<String>()
        val array = JSONArray(json)
        for (i in 0 until array.length()) {
            val entry = array.getJSONObject(i)
            val ips = entry.optJSONArray("ips") ?: continue
            for (j in 0 until ips.length()) {
                result.add(ips.getString(j))
            }
        }
        return result.toList()
    }

    private fun readCache(file: File): List<String> = try {
        val array = JSONArray(file.readText())
        List(array.length()) { array.getString(it) }
    } catch (e: Exception) {
        Log.w(TAG, "Failed to read cache", e)
        emptyList()
    }

    private fun writeCache(file: File, ips: List<String>) {
        try {
            val array = JSONArray()
            ips.forEach { array.put(it) }
            file.writeText(array.toString())
        } catch (e: Exception) {
            Log.w(TAG, "Failed to write cache", e)
        }
    }
}
