export function formatDOSDateTime(date: Date, into: DataView, offset = 0) {
  const dosTime = date.getUTCSeconds() >> 1
  | date.getUTCMinutes() << 5
  | date.getUTCHours() << 11

  const dosDate = date.getUTCDate()
  | (date.getUTCMonth() + 1) << 5
  | (date.getUTCFullYear() - 1980) << 9

  into.setUint16(offset, dosTime, true)
  into.setUint16(offset + 2, dosDate, true)
}
