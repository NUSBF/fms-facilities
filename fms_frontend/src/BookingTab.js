import React, { useState } from 'react';

function BookingTab() {
    // Mock equipment data
    const mockEquipment = [
        { id: 1, name: 'M2.020 High speed Centrifuge Beckman Avanti J26 - XP' },
        { id: 2, name: 'M1077 Tissue Culture Hood Class II' },
        { id: 3, name: 'M2.016 Ultra Centrifuge Beckman Optima L-90K' }
    ];

    // Mock bookings data
    const mockBookings = [
        {
            id: 1,
            equipment_id: 1,
            date: '2025-06-30',
            start_time: '11:45',
            end_time: '12:30',
            user_name: 'Kirsty Smith'
        },
        {
            id: 2,
            equipment_id: 1,
            date: '2025-07-01',
            start_time: '09:00',
            end_time: '10:30',
            user_name: 'John Doe'
        }
    ];

    const [selectedEquipment, setSelectedEquipment] = useState(mockEquipment[0]);
    const [currentDate, setCurrentDate] = useState(new Date('2025-06-30'));
    const [view, setView] = useState('Week');
    const [bookings, setBookings] = useState(mockBookings);
    const [isDragging, setIsDragging] = useState(false);
    const [dragStart, setDragStart] = useState(null);
    const [dragEnd, setDragEnd] = useState(null);

    // Generate time slots from 06:00 to 20:00
    const generateTimeSlots = () => {
        const slots = [];
        for (let hour = 6; hour <= 20; hour++) {
            slots.push(`${hour.toString().padStart(2, '0')}:00`);
        }
        return slots;
    };

    // Generate week days
    const generateWeekDays = () => {
        const days = [];
        const startOfWeek = new Date(currentDate);
        startOfWeek.setDate(currentDate.getDate() - currentDate.getDay() + 1); // Monday

        for (let i = 0; i < 7; i++) {
            const day = new Date(startOfWeek);
            day.setDate(startOfWeek.getDate() + i);
            days.push(day);
        }
        return days;
    };

    // Generate month days for day selection
    const generateMonthDays = () => {
        const days = [];
        const year = currentDate.getFullYear();
        const month = currentDate.getMonth();
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        
        for (let day = 1; day <= daysInMonth; day++) {
            days.push(new Date(year, month, day));
        }
        return days;
    };

    // Generate months for month view
    const generateMonths = () => {
        const months = [];
        const year = currentDate.getFullYear();
        
        for (let month = 0; month < 12; month++) {
            months.push(new Date(year, month, 1));
        }
        return months;
    };

    const timeSlots = generateTimeSlots();
    
    // Get appropriate date array based on view
    const getViewDates = () => {
        switch (view) {
            case 'Today':
                return [new Date(currentDate)];
            case 'Day':
                return generateMonthDays();
            case 'Week':
                return generateWeekDays();
            case 'Month':
                return generateMonths();
            default:
                return generateWeekDays();
        }
    };

    const viewDates = getViewDates();

    // Check if a date has any bookings
    const getBookingsForDate = (date) => {
        const dateStr = date.toISOString().split('T')[0];
        return bookings.filter(booking => 
            booking.equipment_id === selectedEquipment.id &&
            booking.date === dateStr
        );
    };

    // Get bookings for a month
    const getBookingsForMonth = (month) => {
        const year = month.getFullYear();
        const monthNum = month.getMonth();
        return bookings.filter(booking => {
            const bookingDate = new Date(booking.date);
            return booking.equipment_id === selectedEquipment.id &&
                   bookingDate.getFullYear() === year &&
                   bookingDate.getMonth() === monthNum;
        });
    };

    // Check if a time slot is booked
    const getBookingForSlot = (date, time) => {
        const dateStr = date.toISOString().split('T')[0];
        return bookings.find(booking => 
            booking.equipment_id === selectedEquipment.id &&
            booking.date === dateStr &&
            time >= booking.start_time &&
            time < booking.end_time
        );
    };

    // Convert time to minutes for calculations
    const timeToMinutes = (time) => {
        const [hours, minutes] = time.split(':').map(Number);
        return hours * 60 + minutes;
    };

    // Handle mouse down for dragging
    const handleMouseDown = (date, time) => {
        const dateStr = date.toISOString().split('T')[0];
        const existing = getBookingForSlot(date, time);
        
        if (!existing) {
            setIsDragging(true);
            setDragStart({ date: dateStr, time });
            setDragEnd({ date: dateStr, time });
        }
    };

    // Handle mouse over for dragging
    const handleMouseOver = (date, time) => {
        if (isDragging && dragStart) {
            const dateStr = date.toISOString().split('T')[0];
            if (dateStr === dragStart.date) {
                setDragEnd({ date: dateStr, time });
            }
        }
    };

    // Handle mouse up to complete booking
    const handleMouseUp = () => {
        if (isDragging && dragStart && dragEnd) {
            const startMinutes = timeToMinutes(dragStart.time);
            const endMinutes = timeToMinutes(dragEnd.time) + 60; // Add 1 hour to end time
            
            const newBooking = {
                id: Date.now(),
                equipment_id: selectedEquipment.id,
                date: dragStart.date,
                start_time: dragStart.time,
                end_time: `${Math.floor(endMinutes / 60).toString().padStart(2, '0')}:${(endMinutes % 60).toString().padStart(2, '0')}`,
                user_name: 'Your Name'
            };
            
            setBookings([...bookings, newBooking]);
        }
        
        setIsDragging(false);
        setDragStart(null);
        setDragEnd(null);
    };

    // Check if slot is in drag selection
    const isInDragSelection = (date, time) => {
        if (!isDragging || !dragStart || !dragEnd) return false;
        
        const dateStr = date.toISOString().split('T')[0];
        if (dateStr !== dragStart.date) return false;
        
        const currentMinutes = timeToMinutes(time);
        const startMinutes = timeToMinutes(dragStart.time);
        const endMinutes = timeToMinutes(dragEnd.time);
        
        return currentMinutes >= Math.min(startMinutes, endMinutes) && 
               currentMinutes <= Math.max(startMinutes, endMinutes);
    };

    // Navigate dates based on view
    const navigateDate = (direction) => {
        const newDate = new Date(currentDate);
        
        switch (view) {
            case 'Today':
                newDate.setDate(currentDate.getDate() + direction);
                break;
            case 'Day':
                newDate.setMonth(currentDate.getMonth() + direction);
                break;
            case 'Week':
                newDate.setDate(currentDate.getDate() + (direction * 7));
                break;
            case 'Month':
                newDate.setFullYear(currentDate.getFullYear() + direction);
                break;
            default:
                newDate.setDate(currentDate.getDate() + (direction * 7));
        }
        
        setCurrentDate(newDate);
    };

    // Format date range display based on view
    const formatDateRange = () => {
        switch (view) {
            case 'Today':
                return currentDate.toLocaleDateString('en-GB', { 
                    weekday: 'long', 
                    day: 'numeric', 
                    month: 'long', 
                    year: 'numeric' 
                });
            case 'Day':
                return currentDate.toLocaleDateString('en-GB', { 
                    month: 'long', 
                    year: 'numeric' 
                });
            case 'Week':
                const weekDays = generateWeekDays();
                const start = weekDays[0];
                const end = weekDays[6];
                return `${start.getDate()} ${start.toLocaleDateString('en-GB', { month: 'short' })} - ${end.getDate()} ${end.toLocaleDateString('en-GB', { month: 'short' })} ${end.getFullYear()}`;
            case 'Month':
                return currentDate.getFullYear().toString();
            default:
                return '';
        }
    };

    // Set current date to today when Today view is selected
    const handleViewChange = (newView) => {
        if (newView === 'Today') {
            setCurrentDate(new Date());
        }
        setView(newView);
    };

    return (
        <div style={{ padding: '20px' }} onMouseUp={handleMouseUp}>
            {/* Equipment Selector */}
            <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                    Select Equipment:
                </label>
                <select 
                    value={selectedEquipment.id}
                    onChange={(e) => setSelectedEquipment(mockEquipment.find(eq => eq.id === parseInt(e.target.value)))}
                    style={{ 
                        padding: '8px', 
                        border: '1px solid #ddd', 
                        borderRadius: '4px',
                        fontSize: '14px',
                        minWidth: '300px'
                    }}
                >
                    {mockEquipment.map(equipment => (
                        <option key={equipment.id} value={equipment.id}>
                            {equipment.name}
                        </option>
                    ))}
                </select>
            </div>

            {/* Header */}
            <div style={{ marginBottom: '20px' }}>
                <h2 style={{ margin: '0 0 10px 0', fontSize: '18px' }}>
                    {view === 'Day' ? 'Select a day' : 'Select a time slot'}
                </h2>
                
                {/* Navigation */}
                <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center',
                    marginBottom: '10px'
                }}>
                    <button 
                        onClick={() => navigateDate(-1)}
                        style={{ 
                            padding: '8px 12px', 
                            border: '1px solid #ddd', 
                            background: 'white',
                            cursor: 'pointer',
                            borderRadius: '4px'
                        }}
                    >
                        ‹
                    </button>
                    
                    <h3 style={{ margin: 0, fontSize: '16px' }}>
                        {formatDateRange()}
                    </h3>
                    
                    <button 
                        onClick={() => navigateDate(1)}
                        style={{ 
                            padding: '8px 12px', 
                            border: '1px solid #ddd', 
                            background: 'white',
                            cursor: 'pointer',
                            borderRadius: '4px'
                        }}
                    >
                        ›
                    </button>
                    
                    <div style={{ display: 'flex', gap: '5px' }}>
                        {['Today', 'Day', 'Week', 'Month'].map(viewType => (
                            <button
                                key={viewType}
                                onClick={() => handleViewChange(viewType)}
                                style={{
                                    padding: '8px 16px',
                                    border: '1px solid #ddd',
                                    background: view === viewType ? '#007bff' : 'white',
                                    color: view === viewType ? 'white' : 'black',
                                    cursor: 'pointer',
                                    borderRadius: '4px',
                                    fontSize: '14px'
                                }}
                            >
                                {viewType}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Equipment Header - only show for Today and Week views */}
            {(view === 'Today' || view === 'Week') && (
                <div style={{
                    backgroundColor: '#007bff',
                    color: 'white',
                    padding: '10px',
                    textAlign: 'center',
                    fontWeight: 'bold',
                    marginBottom: '0'
                }}>
                    {selectedEquipment.name}
                </div>
            )}

            {/* Calendar Grid for Today and Week views */}
            {(view === 'Today' || view === 'Week') && (
                <div style={{ 
                    border: '1px solid #ddd',
                    borderTop: (view === 'Today' || view === 'Week') ? 'none' : '1px solid #ddd',
                    backgroundColor: 'white'
                }}>
                    {/* Days Header */}
                    <div style={{ display: 'flex' }}>
                        <div style={{ 
                            width: '80px', 
                            padding: '10px', 
                            backgroundColor: '#333',
                            color: 'white',
                            fontSize: '14px',
                            fontWeight: 'bold',
                            textAlign: 'center'
                        }}>
                            Time
                        </div>
                        {viewDates.map(day => (
                            <div key={day.toISOString()} style={{
                                flex: 1,
                                padding: '10px',
                                backgroundColor: '#007bff',
                                color: 'white',
                                textAlign: 'center',
                                fontSize: '14px',
                                fontWeight: 'bold',
                                borderLeft: '1px solid #0056b3'
                            }}>
                                <div>{day.toLocaleDateString('en-GB', { weekday: 'short' })} {day.getDate()}/{day.getMonth() + 1}</div>
                            </div>
                        ))}
                    </div>

                    {/* Time Slots */}
                    {timeSlots.map(time => (
                        <div key={time} style={{ display: 'flex' }}>
                            <div style={{
                                width: '80px',
                                padding: '15px 10px',
                                backgroundColor: '#f8f9fa',
                                borderTop: '1px solid #ddd',
                                fontSize: '14px',
                                textAlign: 'center'
                            }}>
                                {time}
                            </div>
                            {viewDates.map(day => {
                                const booking = getBookingForSlot(day, time);
                                const inDragSelection = isInDragSelection(day, time);
                                
                                return (
                                    <div
                                        key={`${day.toISOString()}-${time}`}
                                        style={{
                                            flex: 1,
                                            minHeight: '50px',
                                            borderTop: '1px solid #ddd',
                                            borderLeft: '1px solid #ddd',
                                            backgroundColor: booking ? '#e9ecef' : inDragSelection ? '#cce5ff' : '#fffbf0',
                                            cursor: booking ? 'default' : 'pointer',
                                            position: 'relative',
                                            userSelect: 'none'
                                        }}
                                        onMouseDown={() => handleMouseDown(day, time)}
                                        onMouseOver={() => handleMouseOver(day, time)}
                                    >
                                        {booking && (
                                            <div style={{
                                                padding: '5px',
                                                fontSize: '12px',
                                                color: '#333'
                                            }}>
                                                <div style={{ fontWeight: 'bold' }}>
                                                    {booking.start_time} - {booking.end_time}
                                                </div>
                                                <div>{booking.user_name}</div>
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    ))}
                </div>
            )}

            {/* Day Selection Grid */}
            {view === 'Day' && (
                <div>
                    {/* Day Selector */}
                    <div style={{ 
                        border: '1px solid #ddd',
                        backgroundColor: 'white',
                        padding: '15px',
                        marginBottom: '20px'
                    }}>
                        <h3 style={{ marginTop: 0, marginBottom: '15px', textAlign: 'center' }}>
                            Select a day in {currentDate.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })}
                        </h3>
                        <div style={{ 
                            display: 'flex', 
                            flexWrap: 'wrap',
                            gap: '6px',
                            justifyContent: 'center',
                            maxWidth: '100%',
                            margin: '0 auto'
                        }}>
                            {generateMonthDays().map(day => {
                                const isToday = day.toDateString() === new Date().toDateString();
                                const isSelected = day.toDateString() === currentDate.toDateString();
                                const dayBookings = getBookingsForDate(day);
                                const hasBookings = dayBookings.length > 0;
                                
                                return (
                                    <button
                                        key={day.toISOString()}
                                        onClick={() => setCurrentDate(new Date(day))}
                                        style={{
                                            padding: '4px 6px',
                                            border: '1px solid #ddd',
                                            backgroundColor: isSelected ? '#007bff' : isToday ? '#e3f2fd' : hasBookings ? '#fff3e0' : 'white',
                                            color: isSelected ? 'white' : isToday ? '#1976d2' : hasBookings ? '#e65100' : 'black',
                                            cursor: 'pointer',
                                            borderRadius: '4px',
                                            fontSize: '10px',
                                            fontWeight: isToday || isSelected ? 'bold' : 'normal',
                                            transition: 'all 0.2s',
                                            minWidth: '32px',
                                            height: '40px',
                                            display: 'flex',
                                            flexDirection: 'column',
                                            justifyContent: 'center',
                                            alignItems: 'center',
                                            position: 'relative'
                                        }}
                                        onMouseEnter={(e) => {
                                            if (!isSelected) {
                                                e.target.style.backgroundColor = '#f0f0f0';
                                            }
                                        }}
                                        onMouseLeave={(e) => {
                                            if (!isSelected) {
                                                e.target.style.backgroundColor = isToday ? '#e3f2fd' : hasBookings ? '#fff3e0' : 'white';
                                            }
                                        }}
                                    >
                                        <div style={{ fontWeight: 'bold', fontSize: '12px', lineHeight: '1' }}>
                                            {day.getDate()}
                                        </div>
                                        <div style={{ fontSize: '8px', lineHeight: '1', marginTop: '1px' }}>
                                            {day.toLocaleDateString('en-GB', { weekday: 'short' })}
                                        </div>
                                        {hasBookings && (
                                            <div style={{ 
                                                position: 'absolute',
                                                bottom: '1px',
                                                right: '1px',
                                                width: '6px',
                                                height: '6px',
                                                backgroundColor: isSelected ? 'white' : '#e65100',
                                                borderRadius: '50%'
                                            }}></div>
                                        )}
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    {/* Equipment Header */}
                    <div style={{
                        backgroundColor: '#007bff',
                        color: 'white',
                        padding: '10px',
                        textAlign: 'center',
                        fontWeight: 'bold',
                        marginBottom: '0'
                    }}>
                        {selectedEquipment.name} - {currentDate.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })}
                    </div>

                    {/* Calendar Grid for selected day */}
                    <div style={{ 
                        border: '1px solid #ddd',
                        borderTop: 'none',
                        backgroundColor: 'white'
                    }}>
                        {/* Days Header */}
                        <div style={{ display: 'flex' }}>
                            <div style={{ 
                                width: '80px', 
                                padding: '10px', 
                                backgroundColor: '#333',
                                color: 'white',
                                fontSize: '14px',
                                fontWeight: 'bold',
                                textAlign: 'center'
                            }}>
                                Time
                            </div>
                            <div style={{
                                flex: 1,
                                padding: '10px',
                                backgroundColor: '#007bff',
                                color: 'white',
                                textAlign: 'center',
                                fontSize: '14px',
                                fontWeight: 'bold',
                                borderLeft: '1px solid #0056b3'
                            }}>
                                <div>{currentDate.toLocaleDateString('en-GB', { weekday: 'short' })} {currentDate.getDate()}/{currentDate.getMonth() + 1}</div>
                            </div>
                        </div>

                        {/* Time Slots */}
                        {timeSlots.map(time => (
                            <div key={time} style={{ display: 'flex' }}>
                                <div style={{
                                    width: '80px',
                                    padding: '15px 10px',
                                    backgroundColor: '#f8f9fa',
                                    borderTop: '1px solid #ddd',
                                    fontSize: '14px',
                                    textAlign: 'center'
                                }}>
                                    {time}
                                </div>
                                {(() => {
                                    const booking = getBookingForSlot(currentDate, time);
                                    const inDragSelection = isInDragSelection(currentDate, time);
                                    
                                    return (
                                        <div
                                            style={{
                                                flex: 1,
                                                minHeight: '50px',
                                                borderTop: '1px solid #ddd',
                                                borderLeft: '1px solid #ddd',
                                                backgroundColor: booking ? '#e9ecef' : inDragSelection ? '#cce5ff' : '#fffbf0',
                                                cursor: booking ? 'default' : 'pointer',
                                                position: 'relative',
                                                userSelect: 'none'
                                            }}
                                            onMouseDown={() => handleMouseDown(currentDate, time)}
                                            onMouseOver={() => handleMouseOver(currentDate, time)}
                                        >
                                            {booking && (
                                                <div style={{
                                                    padding: '5px',
                                                    fontSize: '12px',
                                                    color: '#333'
                                                }}>
                                                    <div style={{ fontWeight: 'bold' }}>
                                                        {booking.start_time} - {booking.end_time}
                                                    </div>
                                                    <div>{booking.user_name}</div>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })()}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Month Selection Grid */}
            {view === 'Month' && (
                <div>
                    {/* Month Selector */}
                    <div style={{ 
                        border: '1px solid #ddd',
                        backgroundColor: 'white',
                        padding: '20px',
                        marginBottom: '20px'
                    }}>
                        <h3 style={{ marginTop: 0, marginBottom: '20px', textAlign: 'center' }}>
                            Select a month in {currentDate.getFullYear()}
                        </h3>
                        <div style={{ 
                            display: 'grid', 
                            gridTemplateColumns: 'repeat(4, 1fr)', 
                            gap: '15px',
                            maxWidth: '600px',
                            margin: '0 auto'
                        }}>
                            {generateMonths().map(month => {
                                const isCurrentMonth = month.getMonth() === new Date().getMonth() && month.getFullYear() === new Date().getFullYear();
                                const isSelected = month.getMonth() === currentDate.getMonth();
                                const monthBookings = getBookingsForMonth(month);
                                const hasBookings = monthBookings.length > 0;
                                
                                return (
                                    <button
                                        key={month.toISOString()}
                                        onClick={() => setCurrentDate(new Date(month))}
                                        style={{
                                            padding: '15px',
                                            border: '1px solid #ddd',
                                            backgroundColor: isSelected ? '#007bff' : isCurrentMonth ? '#e3f2fd' : hasBookings ? '#fff3e0' : 'white',
                                            color: isSelected ? 'white' : isCurrentMonth ? '#1976d2' : hasBookings ? '#e65100' : 'black',
                                            cursor: 'pointer',
                                            borderRadius: '8px',
                                            fontSize: '14px',
                                            fontWeight: isCurrentMonth || isSelected ? 'bold' : 'normal',
                                            transition: 'all 0.2s',
                                            minHeight: '80px',
                                            display: 'flex',
                                            flexDirection: 'column',
                                            justifyContent: 'center',
                                            alignItems: 'center',
                                            position: 'relative'
                                        }}
                                        onMouseEnter={(e) => {
                                            if (!isSelected) {
                                                e.target.style.backgroundColor = '#f0f0f0';
                                            }
                                        }}
                                        onMouseLeave={(e) => {
                                            if (!isSelected) {
                                                e.target.style.backgroundColor = isCurrentMonth ? '#e3f2fd' : hasBookings ? '#fff3e0' : 'white';
                                            }
                                        }}
                                    >
                                        <div style={{ fontSize: '16px', fontWeight: 'bold', marginBottom: '5px' }}>
                                            {month.toLocaleDateString('en-GB', { month: 'long' })}
                                        </div>
                                        {hasBookings && (
                                            <div style={{ 
                                                fontSize: '12px', 
                                                color: isSelected ? 'white' : '#666',
                                                textAlign: 'center'
                                            }}>
                                                {monthBookings.length} booking{monthBookings.length !== 1 ? 's' : ''}
                                            </div>
                                        )}
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    {/* Equipment Header */}
                    <div style={{
                        backgroundColor: '#007bff',
                        color: 'white',
                        padding: '10px',
                        textAlign: 'center',
                        fontWeight: 'bold',
                        marginBottom: '0'
                    }}>
                        {selectedEquipment.name} - {currentDate.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })}
                    </div>

                    {/* Calendar Grid for selected month */}
                    <div style={{ 
                        border: '1px solid #ddd',
                        borderTop: 'none',
                        backgroundColor: 'white'
                    }}>
                        {/* Weekday Header */}
                        <div style={{ display: 'flex' }}>
                            {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((dayName, index) => (
                                <div key={index} style={{
                                    flex: 1,
                                    padding: '10px',
                                    backgroundColor: '#007bff',
                                    color: 'white',
                                    textAlign: 'center',
                                    fontSize: '14px',
                                    fontWeight: 'bold',
                                    borderLeft: index > 0 ? '1px solid #0056b3' : 'none'
                                }}>
                                    {dayName}
                                </div>
                            ))}
                        </div>

                        {/* Calendar month grid */}
                        {(() => {
                            const startOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
                            const endOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
                            const startDate = new Date(startOfMonth);
                            startDate.setDate(startDate.getDate() - startOfMonth.getDay()); // Start from Sunday
                            
                            const weeks = [];
                            let currentWeekStart = new Date(startDate);
                            
                            while (currentWeekStart <= endOfMonth) {
                                const week = [];
                                for (let i = 0; i < 7; i++) {
                                    const day = new Date(currentWeekStart);
                                    day.setDate(currentWeekStart.getDate() + i);
                                    week.push(day);
                                }
                                weeks.push(week);
                                currentWeekStart.setDate(currentWeekStart.getDate() + 7);
                            }
                            
                            return weeks.map((week, weekIndex) => (
                                <div key={weekIndex} style={{ display: 'flex' }}>
                                    {week.map((day, dayIndex) => {
                                        const isCurrentMonth = day.getMonth() === currentDate.getMonth();
                                        const isToday = day.toDateString() === new Date().toDateString();
                                        const dayBookings = getBookingsForDate(day);
                                        const hasBookings = dayBookings.length > 0 && isCurrentMonth;
                                        
                                        return (
                                            <div
                                                key={dayIndex}
                                                style={{
                                                    flex: 1,
                                                    minHeight: '60px',
                                                    borderTop: '1px solid #ddd',
                                                    borderLeft: dayIndex > 0 ? '1px solid #ddd' : 'none',
                                                    backgroundColor: !isCurrentMonth ? '#f8f9fa' : 
                                                                   isToday ? '#e3f2fd' :
                                                                   hasBookings ? '#fff3e0' : 'white',
                                                    cursor: (hasBookings && isCurrentMonth) ? 'pointer' : 'default',
                                                    position: 'relative',
                                                    padding: '8px',
                                                    display: 'flex',
                                                    flexDirection: 'column',
                                                    justifyContent: 'flex-start',
                                                    opacity: isCurrentMonth ? 1 : 0.5
                                                }}
                                                onClick={() => {
                                                    if (hasBookings && isCurrentMonth) {
                                                        setCurrentDate(new Date(day));
                                                        setView('Day');
                                                    }
                                                }}
                                                onMouseEnter={(e) => {
                                                    if (hasBookings && isCurrentMonth) {
                                                        e.target.style.backgroundColor = '#ffcc80';
                                                    }
                                                }}
                                                onMouseLeave={(e) => {
                                                    if (hasBookings && isCurrentMonth) {
                                                        e.target.style.backgroundColor = '#fff3e0';
                                                    }
                                                }}
                                            >
                                                <div style={{ 
                                                    fontSize: '14px', 
                                                    fontWeight: isToday ? 'bold' : 'normal',
                                                    color: isToday ? '#1976d2' : isCurrentMonth ? 'black' : '#999',
                                                    marginBottom: '4px'
                                                }}>
                                                    {day.getDate()}
                                                </div>
                                                {hasBookings && isCurrentMonth && (
                                                    <div style={{
                                                        fontSize: '10px',
                                                        color: '#e65100',
                                                        fontWeight: 'bold',
                                                        textAlign: 'center'
                                                    }}>
                                                        {dayBookings.length} booking{dayBookings.length !== 1 ? 's' : ''}
                                                    </div>
                                                )}
                                            </div>
                                        );
                                    })}
                                </div>
                            ));
                        })()}
                    </div>
                </div>
            )}

            {/* Instructions */}
            <div style={{ 
                marginTop: '10px', 
                fontSize: '14px', 
                color: '#666',
                fontStyle: 'italic',
                textAlign: 'center'
            }}>
                {view === 'Today' || view === 'Week' ? 
                    'Drag on an empty space to book a time slot' :
                    view === 'Day' ?
                    'Click on a day to view its booking calendar' :
                    'Click on a month to view its days'
                }
            </div>
        </div>
    );
}

export default BookingTab;
