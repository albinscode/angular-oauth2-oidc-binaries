// see: https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#The_.22Unicode_Problem.22
export function b64DecodeUnicode(str) {
    const base64 = str.replace(/\-/g, '+').replace(/\_/g, '/');
    return decodeURIComponent(atob(base64)
        .split('')
        .map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    })
        .join(''));
}
export function base64UrlEncode(str) {
    const base64 = btoa(str);
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYmFzZTY0LWhlbHBlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3Byb2plY3RzL2xpYi9zcmMvYmFzZTY0LWhlbHBlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSw0SEFBNEg7QUFDNUgsTUFBTSxVQUFVLGdCQUFnQixDQUFDLEdBQUc7SUFDbEMsTUFBTSxNQUFNLEdBQUcsR0FBRyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQztJQUUzRCxPQUFPLGtCQUFrQixDQUN2QixJQUFJLENBQUMsTUFBTSxDQUFDO1NBQ1QsS0FBSyxDQUFDLEVBQUUsQ0FBQztTQUNULEdBQUcsQ0FBQyxVQUFTLENBQUM7UUFDYixPQUFPLEdBQUcsR0FBRyxDQUFDLElBQUksR0FBRyxDQUFDLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQy9ELENBQUMsQ0FBQztTQUNELElBQUksQ0FBQyxFQUFFLENBQUMsQ0FDWixDQUFDO0FBQ0osQ0FBQztBQUVELE1BQU0sVUFBVSxlQUFlLENBQUMsR0FBRztJQUNqQyxNQUFNLE1BQU0sR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7SUFDekIsT0FBTyxNQUFNO1NBQ1YsT0FBTyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUM7U0FDbkIsT0FBTyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUM7U0FDbkIsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUMsQ0FBQztBQUN2QixDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLy8gc2VlOiBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvV2luZG93QmFzZTY0L0Jhc2U2NF9lbmNvZGluZ19hbmRfZGVjb2RpbmcjVGhlXy4yMlVuaWNvZGVfUHJvYmxlbS4yMlxuZXhwb3J0IGZ1bmN0aW9uIGI2NERlY29kZVVuaWNvZGUoc3RyKSB7XG4gIGNvbnN0IGJhc2U2NCA9IHN0ci5yZXBsYWNlKC9cXC0vZywgJysnKS5yZXBsYWNlKC9cXF8vZywgJy8nKTtcblxuICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KFxuICAgIGF0b2IoYmFzZTY0KVxuICAgICAgLnNwbGl0KCcnKVxuICAgICAgLm1hcChmdW5jdGlvbihjKSB7XG4gICAgICAgIHJldHVybiAnJScgKyAoJzAwJyArIGMuY2hhckNvZGVBdCgwKS50b1N0cmluZygxNikpLnNsaWNlKC0yKTtcbiAgICAgIH0pXG4gICAgICAuam9pbignJylcbiAgKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGJhc2U2NFVybEVuY29kZShzdHIpOiBzdHJpbmcge1xuICBjb25zdCBiYXNlNjQgPSBidG9hKHN0cik7XG4gIHJldHVybiBiYXNlNjRcbiAgICAucmVwbGFjZSgvXFwrL2csICctJylcbiAgICAucmVwbGFjZSgvXFwvL2csICdfJylcbiAgICAucmVwbGFjZSgvPS9nLCAnJyk7XG59XG4iXX0=