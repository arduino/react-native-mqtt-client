package com.github.emotokcak.reactnative.mqtt

import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReadableType

/**
 * Requires a string value from a given `ReadableMap`.
 *
 * @param key
 *
 *   Key associated with the value to be obtained.
 *
 * @return
 *
 *   String value associated with `key`.
 *
 * @throws IllegalArgumentException
 *
 *   If there is no value associated with `key`,
 *   or if the value associated with `key` is not a string.
 */
fun ReadableMap.getRequiredString(key: String): String {
    if (!this.hasKey(key)) {
        throw IllegalArgumentException("no value is associated with $key")
    }
    if (this.getType(key) != ReadableType.String) {
        throw IllegalArgumentException(
            "$key must be associated with a string" +
                " but ${this.getType(key)} was given"
        )
    }
    return this.getString(key)!! // should not be null
}

/**
 * Requires an integer value from a given `ReadableMap`.
 *
 * @param key
 *
 *   Key associated with the value to be obtained.
 *
 * @return
 *
 *   Integer value associated with `key`.
 *
 * @throws IllegalArgumentException
 *
 *   If there is no value associated with `key`,
 *   or if the value associated with `key` is not a number.
 */
fun ReadableMap.getRequiredInt(key: String): Int {
    if (!this.hasKey(key)) {
        throw IllegalArgumentException("no value is associated with $key")
    }
    if (this.getType(key) != ReadableType.Number) {
        throw IllegalArgumentException(
            "$key must be associated with an integer" +
                " but ${this.getType(key)} was given"
        )
    }
    return this.getInt(key)
}

/**
 * Obtains an optional string value from a given `ReadableMap`.
 *
 * @param key
 *
 *   Key associated with the value to be obtained.
 *
 * @return
 *
 *   String value associated with `key`.
 *   `null` if no value is associated with `key`.
 *
 * @throws IllegalArgumentException
 *
 *   If the value associated with `key` is not a string.
 */
fun ReadableMap.getOptionalString(key: String): String? {
    if (!this.hasKey(key)) {
        return null
    }
    if (this.getType(key) != ReadableType.String) {
        throw IllegalArgumentException(
            "$key must be associated with a string" +
                " but ${this.getType(key)} was given"
        )
    }
    return this.getString(key)
}

/**
 * Obtains an optional map value from a given `ReadableMap`.
 *
 * @param key
 *
 *   Key associated with the value to be obtained.
 *
 * @return
 *
 *   Map value associated with `key`.
 *   `null` if no value is associated with `key`.
 *
 * @throws IllegalArgumentException
 *
 *   If the value associated with `key` is not a map.
 */
fun ReadableMap.getOptionalMap(key: String): ReadableMap? {
    if (!this.hasKey(key)) {
        return null
    }
    if (this.getType(key) != ReadableType.Map) {
        throw IllegalArgumentException(
            "$key must be associated with a map" +
                " but ${this.getType(key)} was given"
        )
    }
    return this.getMap(key)
}

/**
* Obtains an optional Boolean value from a given `ReadableMap`.
*
* @param key
*
*   Key associated with the value to be obtained.
*
* @return
*
*   Boolean value associated with `key`.
*   `false` if no value is associated with `key`.
*
* @throws IllegalArgumentException
*
*   If the value associated with `key` is not a Boolean.
*/
fun ReadableMap.getRequiredBoolean(key: String): Boolean {
  if (!this.hasKey(key)) {
    return false
  }
  if (this.getType(key) != ReadableType.Boolean) {
    throw IllegalArgumentException(
      "$key must be associated with a Boolean" +
        " but ${this.getType(key)} was given"
    )
  }
  return this.getBoolean(key)
}