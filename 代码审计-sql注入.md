# SQL注入点代码详细解析
文档中针对CRMEB Java版本系统，共定位出2个后台SQL注入点，均源于**SQL直接拼接**或**误用MyBatis的${}占位符**（非预编译），且未对用户输入做有效过滤。以下从漏洞位置、核心代码、注入原理、触发条件四方面逐一解析。


## 一、SQL注入点1：核销订单查询接口（后台）
### 1. 漏洞基础信息
- **影响接口**：后台核销订单列表查询接口  
  - 请求路径：`api/admin/system/store/order/list`  
  - 请求方法：POST  
  - 权限控制：需拥有`admin:system:order:list`权限（登录后台后触发）  
- **核心风险文件**：  
  - Mapper层：`crmeb-service/src/main/resources/mapper/store/StoreOrderMapper.xml`  
  - Dao层：`crmeb-service/src/main/java/com/zbkj/service/dao/StoreOrderDao.java`  
  - Service层：核销订单相关Service实现类（如`StoreOrderServiceImpl`）  
  - Controller层：`SystemWrite0ffOrderController.java`  


### 2. 核心代码分层解析
#### （1）Mapper层：误用${}占位符（风险根源）
MyBatis中，`${}`会将参数**直接替换为字符串**（无预编译），而`#{}`会生成预编译参数（安全）。该注入点的Mapper文件直接使用`${where}`拼接SQL条件，为注入埋下隐患：
```xml
<!-- StoreOrderMapper.xml 关键代码 -->
<mapper namespace="com.zbkj.service.dao.StoreOrderDao">
    <!-- 1. 订单总金额查询：${where}直接拼接条件 -->
    <select id="getTotalPrice" resultType="java.math.BigDecimal">
        select sum(pay_price) from eb_store_order where ${where} and refund_status=0
    </select>
    <!-- 2. 退款总金额查询：${where}直接拼接条件 -->
    <select id="getRefundPrice" resultType="java.math.BigDecimal">
        select sum(refund_price) from eb_store_order where ${where} and refund_status=2
    </select>
    <!-- 3. 退款总单数查询：${where}直接拼接条件 -->
    <select id="getRefundTotal" resultType="java.lang.Integer">
        select count(id) from eb_store_order where ${where} and refund_status=2
    </select>
</mapper>
```
- 风险点：`${where}`参数由Service层动态拼接，若拼接内容包含用户可控输入且无过滤，将直接篡改SQL结构。


#### （2）Dao层：未对参数做校验
Dao层接口定义了接收`String where`参数的方法，未限制参数格式或内容：
```java
// StoreOrderDao.java 关键代码
public interface StoreOrderDao extends BaseMapper<StoreOrder> {
    // 订单总金额：直接接收String类型的where条件
    BigDecimal getTotalPrice(String where);
    // 退款总金额：直接接收String类型的where条件
    BigDecimal getRefundPrice(String where);
    // 退款总单数：直接接收String类型的where条件
    Integer getRefundTotal(String where);
}
```


#### （3）Service层：用户输入直接拼接SQL（注入触发点）
Service层的`getWrite0ffList`方法中，动态拼接`where`字符串，其中**用户输入的`keywords`未做任何过滤/转义**，直接拼接到SQL中：
```java
// StoreOrderServiceImpl 关键代码（核销订单查询逻辑）
@Override
public SystemWrite0ffOrderResponse getWrite0ffList(SystemWrite0ffOrderSearchRequest request, PageParamRequest pageParamRequest) {
    LambdaQueryWrapper<StoreOrder> lambdaQueryWrapper = new LambdaQueryWrapper<>();
    // 初始条件：未删除、配送类型为2
    String where = "is_del=0 and shipping_type=2";

    // 1. 拼接时间条件（安全）：DateUtil格式化处理，输入不可控
    if (!StringUtils.isBlank(request.getDateLimit())) {
        DateLimitUtilVo dateLimit = DateUtil.getDateLimit(request.getDateLimit());
        where += " and (create_time between '" + dateLimit.getStartTime() + "' and '" + dateLimit.getEndTime() + "')";
    }

    // 2. 拼接关键字条件（高危！无过滤）：keywords为用户直接输入
    if (!StringUtils.isBlank(request.getKeywords())) {
        // 拼接real_name（模糊查询）、user_phone、order_id、id等字段
        where += " and (real_name like '%" + request.getKeywords() + "%' " +
                 "or user_phone='" + request.getKeywords() + "' " +
                 "or order_id='" + request.getKeywords() + "' " +
                 "or id='" + request.getKeywords() + "')";
    }

    // 3. 拼接门店ID（安全）：Integer类型，强制数字校验
    if (request.getStoreId() != null && request.getStoreId() > 0) {
        where += " and store_id=" + request.getStoreId();
    }

    // 调用Dao层方法，传入拼接后的where条件（风险传递）
    BigDecimal totalPrice = dao.getTotalPrice(where);
    BigDecimal refundPrice = dao.getRefundPrice(where);
    Integer refundTotal = dao.getRefundTotal(where);

    // 组装返回结果...
    SystemWrite0ffOrderResponse response = new SystemWrite0ffOrderResponse();
    response.setOrderTotalPrice(totalPrice);
    // ...其他赋值逻辑
    return response;
}
```
- 关键风险：`request.getKeywords()`是用户可控参数（如输入`' or '1'='1`），直接拼接到SQL中，会破坏原查询条件逻辑。


#### （4）Controller层：参数无过滤传递
Controller层接收前端传入的`SystemWrite0ffOrderSearchRequest`参数，未对`keywords`做格式校验或注入过滤，直接传递给Service层：
```java
// SystemWrite0ffOrderController.java 关键代码
@RestController
@RequestMapping("api/admin/system/store/order")
@Api(tags = "设置--提货点-核销订单")
public class SystemWrite0ffOrderController {
    @Autowired
    private StoreOrderService storeOrderService;

    // 核销订单分页列表接口
    @PreAuthorize("hasAuthority('admin:system:order:list')")
    @ApiOperation(value = "分页列表")
    @RequestMapping(value = "/list", method = RequestMethod.POST)
    public CommonResult<SystemWrite0ffOrderResponse> getList(
            @Validated SystemWrite0ffOrderSearchRequest request,  // 接收参数
            @Validated PageParamRequest pageParamRequest) {
        // 直接调用Service，无参数过滤
        return CommonResult.success(storeOrderService.getWrite0ffList(request, pageParamRequest));
    }
}

// 参数实体类：SystemWrite0ffOrderSearchRequest
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
public class SystemWrite0ffOrderSearchRequest implements Serializable {
    private static final Long serialVersionUID = 1L;
    private Integer storeId;       // 门店ID（Integer，安全）
    private String dateLimit;      // 时间范围（格式化处理，安全）
    private String keywords;       // 关键字（String，用户可控，无校验）
}
```


### 3. 注入原理与触发示例
#### （1）注入原理
当用户在`keywords`中输入恶意SQL片段（如`' or '1'='1 -- `），拼接后的`where`条件会变为：
```sql
is_del=0 and shipping_type=2 
and (real_name like '%' or '1'='1 -- %' 
or user_phone='' or '1'='1 -- ' 
or order_id='' or '1'='1 -- ' 
or id='' or '1'='1 -- ')
```
- `'1'='1`使条件恒为真，`-- `注释掉后续SQL，导致查询出**所有核销订单**（越权获取数据）；
- 若输入`' ; drop table eb_store_order; -- `，可能触发删除表（需数据库权限支持）。


#### （2）触发示例（POST请求）
```http
POST /api/admin/system/store/order/list HTTP/1.1
Host: 目标域名
Cookie: 登录后的SESSIONID（需后台权限）
Content-Type: application/json

{
    "dateLimit": "",
    "keywords": "' or '1'='1 -- ",  // 恶意注入 payload
    "storeId": null
}
```


## 二、SQL注入点2：商品列表查询接口（后台）
### 1. 漏洞基础信息
- **影响接口**：后台商品分页列表查询接口  
  - 请求路径：`api/admin/store/product/list`  
  - 请求方法：GET  
  - 权限控制：需拥有`admin:product:list`权限（登录后台后触发）  
- **核心风险文件**：  
  - Service层：`StoreProductServiceImpl.java`（QueryWrapper拼接风险）  
  - Controller层：`StoreProductController.java`  
  - 参数实体类：`StoreProductSearchRequest.java`  


### 2. 核心代码分层解析
#### （1）Controller层：接口与参数定义
Controller层接收`StoreProductSearchRequest`参数，其中`cateId`（分类ID，多个用逗号分隔）为String类型，用户可控且无校验：
```java
// StoreProductController.java 关键代码
@RestController
@RequestMapping("api/admin/store/product")
@Api(tags = "商品")
public class StoreProductController {
    @Autowired
    private StoreProductService storeProductService;

    // 商品分页列表接口
    @PreAuthorize("hasAuthority('admin:product:list')")
    @ApiOperation(value = "分页列表")
    @RequestMapping(value = "/list", method = RequestMethod.GET)
    public CommonResult<CommonPage<StoreProductResponse>> getList(
            @Validated StoreProductSearchRequest request,  // 接收参数
            @Validated PageParamRequest pageParamRequest) {
        // 直接调用Service，无参数过滤
        return CommonResult.success(CommonPage.restPage(storeProductService.getAdminList(request, pageParamRequest)));
    }
}

// 参数实体类：StoreProductSearchRequest
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
public class StoreProductSearchRequest implements Serializable {
    private static final Long serialVersionUID = 1L;
    @NotNull(message = "商品类型不能为空")
    @Range(min = 1, max = 5, message = "未知的商品类型")
    private int type;              // 商品类型（int，有范围校验，安全）
    private String cateId;         // 分类ID（String，多ID用逗号分隔，无校验）
    private String keywords;       // 关键字（String，用户可控）
}
```


#### （2）Service层：QueryWrapper拼接风险
Service层的`getAdminList`方法中，使用MyBatis-Plus的`QueryWrapper`构建查询条件，若对`cateId`的处理为**直接字符串拼接**（而非参数化），则会触发注入：
```java
// StoreProductServiceImpl.java 关键代码（推测，基于文档描述）
@Override
public PageInfo<StoreProductResponse> getAdminList(StoreProductSearchRequest request, PageParamRequest pageParamRequest) {
    QueryWrapper<StoreProduct> queryWrapper = new QueryWrapper<>();
    // 1. 商品类型条件（安全：int类型+Range校验）
    queryWrapper.eq("type", request.getType());
    // 2. 分类ID条件（高危！直接拼接String）
    if (!StringUtils.isBlank(request.getCateId())) {
        // 错误示例：直接拼接cateId（无参数化）
        queryWrapper.in("cate_id", request.getCateId().split(",")); 
        // 若底层处理为：where cate_id in (1' or '1'='1)，则触发注入
        // 或更直接的拼接：queryWrapper.apply("cate_id in ({0})", request.getCateId());
    }
    // 3. 关键字条件（风险：若用like拼接无转义）
    if (!StringUtils.isBlank(request.getKeywords())) {
        queryWrapper.and(w -> w.like("product_name", request.getKeywords())
                               .or().like("product_brief", request.getKeywords()));
    }
    // 分页查询
    IPage<StoreProduct> page = page(new Page<>(pageParamRequest.getPage(), pageParamRequest.getLimit()), queryWrapper);
    // 结果转换...
    return new PageInfo<>(page.getRecords().stream().map(this::convertToResponse).collect(Collectors.toList()));
}
```
- 风险点：`request.getCateId()`为String类型（如用户输入`1' or '1'='1`），若后台直接按“逗号分割”后拼接`in`条件，会生成非法SQL：  
  `where type=2 and cate_id in (1' or '1'='1)`  
  此时`'1'='1`使条件恒为真，查询出**所有分类的商品**（越权）。


### 3. 注入原理与触发示例
#### （1）注入原理
用户在`cateId`参数中输入恶意值（如`1' or '1'='1 -- `），若后台未对`cateId`做“是否为数字”校验，直接拼接`in`条件，会导致SQL逻辑被篡改：
- 正常`cateId=1,2`：`cate_id in (1,2)`（安全）；
- 恶意`cateId=1' or '1'='1`：`cate_id in (1' or '1'='1)`（条件恒真，查询所有商品）。


#### （2）触发示例（GET请求）
```http
GET /api/admin/store/product/list?page=1&limit=20&type=2&cateId=1'%20or%20'1'='1%20-- &keywords= HTTP/1.1
Host: 目标域名
Cookie: 登录后的SESSIONID（需后台权限）
```
- 注：`%20`是空格的URL编码，`-- `用于注释后续SQL，避免语法错误。


## 三、注入点共性问题与安全对比
### 1. 共性风险原因
| 风险点                | 具体表现                                  | 危害                                  |
|-----------------------|-------------------------------------------|---------------------------------------|
| 误用MyBatis占位符     | 使用`${}`（直接替换）而非`#{}`（预编译）   | 绕过预编译，直接篡改SQL结构           |
| 用户输入无过滤        | `keywords`/`cateId`未做“数字校验”“转义”   | 恶意输入直接进入SQL条件               |
| 字符串直接拼接        | 使用`+`拼接SQL片段（如`where += "and ..."`）| 破坏SQL语法，注入恶意逻辑             |
| 权限控制不兜底        | 仅依赖后台登录权限，未限制输入参数范围     | 后台低权限用户可利用注入越权获取数据  |


### 2. 安全代码对比（以注入点1为例）
#### （1）不安全代码（原代码）
```java
// Service层拼接keywords（无过滤）
where += " and (real_name like '%" + request.getKeywords() + "%' or user_phone='" + request.getKeywords() + "')";
```

#### （2）安全代码（优化方案）
```java
// 1. 使用MyBatis-Plus的参数化查询（避免字符串拼接）
QueryWrapper<StoreOrder> queryWrapper = new QueryWrapper<>();
queryWrapper.eq("is_del", 0).eq("shipping_type", 2);
// 关键字参数化（like转义）
if (!StringUtils.isBlank(request.getKeywords())) {
    String keywords = "%" + request.getKeywords() + "%";
    queryWrapper.and(w -> w.like("real_name", keywords)
                           .or().eq("user_phone", request.getKeywords())
                           .or().eq("order_id", request.getKeywords())
                           .or().eq("id", request.getKeywords()));
}
// 2. Mapper层删除${where}，使用参数化方法
<select id="getTotalPrice" resultType="java.math.BigDecimal">
    select sum(pay_price) from eb_store_order
    <where>
        is_del=0 and shipping_type=2
        <if test="keywords != null">
            and (real_name like #{keywords} or user_phone=#{keywords})
        </if>
    </where>
</select>




用法：
要理解这段代码，我们需要从 **MyBatis框架的核心概念** 入手（这段代码是MyBatis的「SQL映射文件」），再逐行拆解每个元素的作用、用法，最后结合「SQL注入风险」讲清关键问题。以下是通俗且详细的解释：


## 一、先搞懂基础：什么是MyBatis Mapper.xml？
MyBatis是Java项目中常用的「ORM框架」（简单说：帮Java代码和数据库交互的工具），它的核心思想是 **“把SQL语句和Java代码分开写”** ——  
Java代码里只定义“要调用哪个SQL”的接口（比如`StoreOrderDao`接口），而具体的SQL语句则写在「Mapper.xml文件」里。  
你提供的这段代码，就是专门为 `StoreOrderDao` 接口服务的SQL映射文件，作用是：定义「订单总金额、退款总金额、退款总单数」这3个查询的SQL逻辑。


## 二、逐行拆解代码：概念+用法
我们按代码结构一步步拆，每个标签/属性都对应具体功能：

### 1. 最外层：`<mapper>` 标签与 `namespace` 属性
```xml
<mapper namespace="com.zbkj.service.dao.StoreOrderDao">
    <!-- 里面放具体的SQL查询 -->
</mapper>
```
- **概念**：`<mapper>` 是Mapper.xml的根标签，必须有 `namespace` 属性，它是「SQL和Java接口的“绑定钥匙”」。  
- **用法规则**：  
  `namespace` 的值必须和「对应的Java接口（Dao接口）的全类名完全一致」。  
  比如这里 `namespace="com.zbkj.service.dao.StoreOrderDao"`，就意味着：  
  这个XML里的所有SQL，都属于 `StoreOrderDao` 接口（Java代码里的 `StoreOrderDao` 接口，会通过这个属性找到这里的SQL）。  
- **举个例子**：Java里的 `StoreOrderDao` 接口有个方法 `BigDecimal getTotalPrice(String where)`，它会自动对应到这个XML里 `id="getTotalPrice"` 的SQL。


### 2. 核心查询：`<select>` 标签（查数据专用）
MyBatis用不同标签对应数据库操作：  
- `<select>`：查数据（对应SQL的`SELECT`）；  
- `<insert>`：插数据（对应`INSERT`）；  
- `<update>`/`<delete>`：改/删数据。  

你这段代码里3个都是 `<select>`，因为都是“查金额、查数量”的需求。


### 3. `<select>` 里的关键属性：`id` 和 `resultType`
以第一个查询为例：
```xml
<select id="getTotalPrice" resultType="java.math.BigDecimal">
    select sum(pay_price) from eb_store_order where ${where} and refund_status=0
</select>
```

#### （1）`id="getTotalPrice"`
- **概念**：`id` 是这个SQL的“唯一名字”，用来和「Java接口里的方法名绑定」。  
- **用法规则**：  
  `id` 的值必须和 `StoreOrderDao` 接口里的「方法名完全一致」。  
  比如：  
  - XML里 `id="getTotalPrice"` → 对应 `StoreOrderDao` 接口的 `BigDecimal getTotalPrice(String where)` 方法；  
  - XML里 `id="getRefundPrice"` → 对应接口的 `BigDecimal getRefundPrice(String where)` 方法。  
- **作用**：Java代码调用 `storeOrderDao.getTotalPrice(where)` 时，MyBatis会通过 `id` 找到这个SQL并执行。


#### （2）`resultType="java.math.BigDecimal"`
- **概念**：`resultType` 是「SQL查询结果的“数据类型”」，告诉MyBatis：执行SQL后，要把数据库返回的结果转换成什么Java类型。  
- **用法规则**：  
  根据SQL的查询结果来定：  
  - 第一个SQL `select sum(pay_price)`：查的是“金额总和”（数据库里是小数，且可能很大），所以用 `java.math.BigDecimal`（Java里处理大额小数的类型，比`double`更精准）；  
  - 第三个SQL `select count(id)`：查的是“数量”（整数），所以用 `java.lang.Integer`。  
- **作用**：MyBatis会自动把SQL结果转成 `resultType` 指定的类型，比如查总金额后，直接返回 `BigDecimal` 类型给Java代码，不用手动转换。


### 4. 最关键（也是最危险）的：`${where}` 是什么？
这是这段代码的核心，也是导致SQL注入的根源！先搞懂它的语法：

#### （1）概念：`${}` 是MyBatis的「文本替换语法」
MyBatis里有两种传递参数的方式：`${}` 和 `#{}`，两者区别巨大：  
| 语法   | 作用逻辑                                  | 安全性                |
|--------|-------------------------------------------|-----------------------|
| `${参数名}` | 直接把参数的“字符串内容”拼到SQL里（无处理） | 危险！易引发SQL注入   |
| `#{参数名}` | 先把SQL里的 `#{}` 换成“问号占位符”（预编译），再传参数 | 安全！能防SQL注入     |

#### （2）`${where}` 在这段代码里的用法
比如Java代码里调用：  
```java
// Service层拼接where参数：“is_del=0 and shipping_type=2”
String where = "is_del=0 and shipping_type=2";
BigDecimal totalPrice = storeOrderDao.getTotalPrice(where);
```
MyBatis会把 `#{where}` 直接替换成参数的字符串内容，最终执行的SQL变成：  
```sql
select sum(pay_price) from eb_store_order where is_del=0 and shipping_type=2 and refund_status=0
```
——这看起来正常，但如果 `where` 参数里包含「用户输入的恶意内容」，问题就来了！

#### （3）为什么危险？（结合之前的SQL注入点）
之前的代码里，`where` 参数是Service层拼接的，其中包含用户可控的 `keywords`（比如用户输入 `' or '1'='1 -- `），拼接后的 `where` 会变成：  
```java
String where = "is_del=0 and shipping_type=2 and (real_name like '%' or '1'='1 -- %' ...)";
```
MyBatis用 `#{where}` 替换后，最终执行的SQL会变成：  
```sql
select sum(pay_price) from eb_store_order where is_del=0 and shipping_type=2 and (real_name like '%' or '1'='1 -- %' ...) and refund_status=0
```
- `'1'='1` 会让SQL条件“恒为真”，导致查询出所有订单的金额；  
- `-- ` 是SQL注释符，会把后面的SQL内容注释掉，避免语法错误。  
这就是「SQL注入漏洞」的由来！


## 三、这段代码的完整执行流程（帮你串起来）
理解“代码怎么跑起来”，能更清楚用法：
1. **Java调用**：Service层需要查“核销订单总金额”，于是调用 `StoreOrderDao` 接口的 `getTotalPrice(where)` 方法，并传入拼接好的 `where` 参数（比如 `is_del=0 and shipping_type=2`）；  
2. **MyBatis匹配**：MyBatis通过 `StoreOrderDao` 的全类名，找到 `namespace` 对应的这个Mapper.xml，再通过 `id="getTotalPrice"` 找到对应的SQL；  
3. **参数替换**：MyBatis用 `where` 参数的内容，直接替换SQL里的 `${where}`，生成最终要执行的SQL；  
4. **执行与返回**：MyBatis把生成的SQL发给数据库执行，拿到“总金额”结果后，自动转成 `BigDecimal` 类型，返回给Service层；  
5. **最终用结果**：Service层把这个总金额封装到响应里，返回给前端（比如后台页面显示“核销订单总金额”）。


## 四、总结：关键考点+安全建议
1. **核心考点**：  
   - Mapper.xml的作用：绑定Dao接口，存放SQL；  
   - `namespace` 必须对应Dao接口全类名；  
   - `id` 必须对应Dao接口方法名；  
   - `resultType` 对应SQL结果的Java类型；  
   - `#{}` 安全（预编译），`${}` 危险（直接拼接，易注入）。

2. **安全建议（修复这段代码的漏洞）**：  
   尽量不用 `${}`，改用MyBatis的「动态SQL标签」（比如 `<where>`、`<if>`）来拼条件，举个修复例子：  
   ```xml
   <select id="getTotalPrice" resultType="java.math.BigDecimal" parameterType="Map">
       select sum(pay_price) from eb_store_order 
       <where>
           <!-- 用<if>判断条件，参数用#{}, 安全！ -->
           <if test="isDel != null">and is_del = #{isDel}</if>
           <if test="shippingType != null">and shipping_type = #{shippingType}</if>
           <!-- 固定条件：退款状态为0 -->
           and refund_status=0
       </where>
   </select>
   ```
   这样即使参数来自用户输入，也会被预编译处理，不会引发SQL注入。
```
